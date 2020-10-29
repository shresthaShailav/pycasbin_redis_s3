# POLICY        
import casbin
from casbin import persist

# REDIS
import redis

# AWS STORAGE
import boto3
s3_client = boto3.client('s3')

# LOGGING
import logging 
logger = logging.getLogger(__name__)

import os
import time

TEMP_PATH = os.path.join(os.getcwd(),'temp')
if not os.path.exists(TEMP_PATH) : os.makedirs(TEMP_PATH)


# POLICY ADAPTER FOR REDIS ----------------------------------------------------
# See :
#        https://casbin.org/docs/en/adapters
#        https://github.com/pycasbin/pycasbin/blob/master/casbin/persist/adapter.py
#        https://github.com/pycasbin/pycasbin/blob/master/casbin/persist/adapters/file_adapter.py
# -----------------------------------------------------------------------------
class RedisPolicyAdapter(persist.Adapter) : 
    """ 
        Adapter for loading policy to Redis

        Specifications : 
            Policies are stored as list 
            Atleast 1 policy is present in Redis.
    """
    def __init__(self, host, port, lkey, tkey) :
        """ 
            host = Redis host
            port = Redis port
            lkey = key to a redis list containing policies
                    each list entry is a policy string
            tkey = key to timestamp val in redis 
                    updated during save policy

            eg : lkey = 'policy_list'

                 (in redis)
                 policy_list = [
                        policy1,
                        policy2,
                        ...
                        ]
        """
        self.host = host
        self.port = port
        self.lkey = lkey 
        self.r = redis.Redis(self.host, self.port, socket_timeout=10)
        self.policies_timestamp_key = tkey

        # check redis
        try : self.r.ping()
        except Exception as e: 
            logger.error("Redis Unreachable. Unable to Read Policies from Redis")
            raise e

        logger.debug(f"Redis PolicyAdapter Initiated.{self.host}:{self.port}->{self.lkey}")


    def load_policy(self, model) : 
        """
            Loads the Policy stored in Redis to our Pycasbin Instance.
        """

        # read policy list from Redis 
        policies = self.r.lrange(self.lkey, 0, -1)

        assert len(policies) > 0 

        # load policies to our enforcer.(pycasbin)
        for policy in policies : 
            persist.load_policy_line(policy.decode('utf-8'), model)
        logger.debug(f"Loaded Policy in {self.lkey} from Redis to Enforcer")


    def save_policy(self, model) : 
        """
            Stores the policy from our Pycasbin Instance to Redis
        """
        policies = []
        if "p" in model.model.keys():
            for key, ast in model.model["p"].items():
                for pvals in ast.policy:
                    policies.append(key + ', ' + ', '.join(pvals))

        if "g" in model.model.keys():
            for key, ast in model.model["g"].items():
                for pvals in ast.policy:
                    policies.append(key + ', ' + ', '.join(pvals))

        assert len(policies) > 0

        # REDIS TRANSACTION ---------------------------------------------------
        # Transactions ensure atomicity of the operation. 
        # Other replicas will not be able to modify policy during transaction, which 
        #   prevents inconsistent state in REDIS.
        
        p = self.r.pipeline()

        # avoid redundancy. Clearing the list
        p.delete(self.lkey)

        # push the policies to redis
        p.rpush(self.lkey, *policies)

        # update policy timestamp in Redis (notify others that policy has changed)
        timestamp = int(time.time() * 1000)
        p.set(self.policies_timestamp_key, timestamp)

        # execute the pipeline
        p.execute()
        # ---------------------------------------------------------------------
        logger.debug("Saved Policy from Enforcer to Redis")



# PolicyManager ---------------------------------------------------------------
#
# PolicyManager manages all the access policy Requirements.
# Access Policy is controlled by a policy file stored in S3
# 
# The Class takes care of loading the policy from S3 to redis and 
# managing all the related updates in a distributed setting
#
# Since it is expected to work in distributed environment, it works as follows :
# 
# 1.Upon __init__ it checks if Redis for policy_timestamp
#   1.1 If policy_timestamp found (which implies policy has already been loaded 
#           by some other instance) , it loads the policy from redis using Redis Adapter
#   1.2 If policy_timestamp not found (which implies it is the first one ),
#           it loads the policy from s3 to redis and then from redis Using Redis Adapter
#
# 2. Upon enforce being called (ie. when others want to check access permission),
#       it checks if the policy is still fresh (i.e some other instances has not changed it)
#       Freshness is measured using policy timestamp. A policy is fresh as long as the 
#       policy timestamp on Redis is equal to the policy timestamp of our current policy
#   2.1 If policy is not fresh : it loads the new policy 
#
# Scenarios : 
# A. Some Instance updates the policy
#       When other instance updates the policy, they 
#       i.   First Update S3 with the new policy
#       ii.  Then they load that policy from S3 to Redis
#       iii. Then they update the policy_timestamp 
#
#       Other instances can detect the change in policy by keeping track of policy timestamp.
#       If their current_policy_timestamp does not match with Redis, they simply update policy from Redis
#           The other instances do not even need to lookup S3
#
# B. Redis Fails/ Restarts with all data gone
#       This is not a problem. After Redis Fails, the First Instance that checks the policy_timestamp
#           will note that the timestamp is None so it will reload the policies for csv and
#           update the timestamp. The only slignt inconvenience is that other instances also 
#           reloads their policy from Redis
#          
# C. Some instance fails midway
#       This too is not a problem. If the instance fails and restarts,
#       It starts from the begining, checks for policies timestamp. It finds one and then uses it. 
#       Doesn't even need to query S3!
#
# The reason for using Redis is to avoid having to lookup S3 for policy updates everytime.( Gets expensive!)
# -----------------------------------------------------------------------------
class PolicyManager : 

    def __init__(
        self,
        redis_endpoint,         # redis containing the set of policies
        policies_key,           # unique key, identifies policies in redis
        policies_timestamp_key, # unique key, identifies last timestamp of policies
        policy_model_path,      # pycasbin policy model file path
        s3_bucket,              # the bucket where we store the policies
        s3_policies_key,        # the key to locate policies in s3
        sync_interval=100,      # how frequently changes are tracked (in seconds)
        ) : 
        
        # policy configurations
        self.host, self.port = redis_endpoint.split(':')
        self.policies_key = policies_key
        self.r = redis.Redis(self.host, self.port, db=0, socket_timeout=10)
        self.s3_bucket = s3_bucket
        self.s3_policies_key = s3_policies_key
        self.default_policy = ['g, admin, admin']

        # for syncing with redis
        self.policies_timestamp_key = policies_timestamp_key
        self.sync_interval = int(sync_interval)
        self.last_sync_at = int(time.time() * 1000)               # the last time we synced with REDIS
        self.last_update_timestamp = 0      # what the last policy timestamp was in REDIS

        # convert sync_interval to milliseconds
        self.sync_interval = self.sync_interval * 1000
        # load policies from S3 to REDIS (only if required)
        self._load_policy_from_s3()

        # adapter to load the policies from redis
        self.adapter = RedisPolicyAdapter(host=self.host, port=self.port, lkey=self.policies_key, tkey=self.policies_timestamp_key)
        self.enforcer = casbin.Enforcer(
            policy_model_path,
            self.adapter
            )

        # Initiate
        self.get_enforcer(sync=True)
        logger.debug("Successfully Initiated PolicyManager")
        
        
    def enforce(self, entity, path, method) : 
        """
            Returns : 
                True : if entity is granted access
                False : if Access not granted

            Caution : 
                the params are case sensitive!
        """
        return self.get_enforcer().enforce(entity, path, method)


    def get_enforcer(self, sync=False) : 
        """
            Returns an PyCasbin enforcer for PolicyEnforcement.
            
            make sure enforcer is accessed through get_enforcer 
            because it takes care of fresh policy management (if necessary)

            sometimes, it's necessary to make sure that the enforcer is up to date with REDIS
            Especially when updating/ writing Policy to REDIS.
            In such cases, use sync = True
        """
        if self._is_policy_fresh(sync=sync) : 
            return self.enforcer
        else : 

            # this is necessary.
            # timestamp mismatch can also occur if Redis loses all data midway
            # In such case, policy is reloaded from s3
            # If Redis did not fail and policy was already loaded, this does nothing
            # so no harm.
            self._load_policy_from_s3(force=False)

            # reload the policy to our enforcer
            self.enforcer.load_policy()

            # to keep track of policy change
            self.last_update_timestamp = self._poll_policy_timestamp() 

            logger.debug("Policy Enforcer Updated")
            return self.enforcer


    def _poll_policy_timestamp(self) :
        """ 
            Polls REDIS for the latest policy timestamp.
            Returns None if not found, otherwise returns an int(timestamp)
        """
        t = self.r.get(self.policies_timestamp_key)
        try : t = int(t) 
        except : t = None
        return t


    def _is_policy_fresh(self, sync=False) : 
        """ 
            A policy is considered fresh if it has the same timestamp as the 
                one in Redis
            Returns :
                True : if the policy list in Redis has not been updated
                False : if policy has been updated

            Note that to avoid querying redis in every request, we set a
            certain sync_interval after which we query redis...
            sync_interval can be reasonably large. 5mins, 10mins,.. 
            policies don't change that often!

            to Force querying Redis, pass sync=True
        """

        cur_timestamp = int(time.time() * 1000)
        if not sync and cur_timestamp - self.last_sync_at < self.sync_interval : 
            logger.debug("Skipped : Policy Sync with Redis." + 
                    f" Less than {self.sync_interval} milliseconds since last Redis poll.")
            return True

        logger.debug("SyncIntervalTimeout/Override. Initiating Policy Sync with Redis")

        if self.last_update_timestamp == self._poll_policy_timestamp() : 
            logger.debug("Policy already in Sync with Redis")
            self.last_sync_at = cur_timestamp
            return True

        # implies policy in Redis has been updated. So the policy is no longer fresh
        logger.debug("Policy not in sync with Redis")
        return False


    def _load_policy_from_s3(self,force=False) :
        """
            Fetches the policy file from database and loads it to Redis. Only if necessary!
            If policy_timestamp key exists in Redis and is not None 
                (which implies that someone else has already loaded from s3 & redis data intact), 
                it does nothing.
            
            We can override this behaviour and load again from S3 by passing (force = True)
                (We do this when the policy in S3 itself has been updated)
        """

        if force or (self._poll_policy_timestamp() is None) :
            try : 
                # download policies to a temporary file
                policy_path = os.path.join(TEMP_PATH, 'policies.csv')
                s3_client.download_file(
                    Bucket = self.s3_bucket,
                    Key = self.s3_policies_key,
                    Filename = policy_path
                )
            except : 
                msg = 'Ensure that S3 bucket contains the specified policy csv file'
                raise self.S3PolicyDownloadFailure(msg)

            try :
                # parse downloaded file and load policy
                policies = []
                with open(policy_path, 'r') as f : 
                    for line in f : 
                        policies.append(line.strip('\n'))
                # you need to have atleast one policy in Redis!
                # all policies must be str
                assert len(policies) > 0         
                assert all(isinstance(s, str) for s in policies)

                # delete temporary file
                try : os.remove(policy_path)
                except : pass

                logger.debug("Policy Fetched from S3")
            except Exception as e: 
                msg = 'Ensure that the policy file consists of atleast 1 policy in appropriate format'
                raise self.S3PolicyParseFailure(msg)

            
            # Load to REDIS
            self._load_policy_to_redis(policies)
        else : 
            logger.debug("Skipped : Policy Load From S3. Found Policy in Redis")

            
    def save_policy_to_s3(self) : 
        """
            Save the Current State of Policy to S3

            Notes : 
            Policy state can change dynamically.
            We do not directly update Policy File
            We use the pycasbin management api to update policies,
                then we save the policy to Redis using RedisPolicyAdapter
                finally we call this method to store from Redis S3
        """

        # current policies
        policies = self.r.lrange(self.policies_key, 0, -1)

        # write updated policies to temp file
        policy_path = os.path.join(TEMP_PATH, 'policies.csv')
        with open(policy_path, 'w') as f : 
            for policy in policies : 
                policy = policy.decode('utf-8')
                f.write(f"{policy}\n")

        # upload to S3
        try : 
            s3_client.upload_file(
                Filename = policy_path,
                Bucket = self.s3_bucket,
                Key = self.s3_policies_key
                )
        except : 
            raise self.S3PolicyUploadFailure
        
        # delete temp local file
        try : os.remove(policy_path)
        except : pass

        logger.debug("Saved REDIS policies to S3")


    def _load_policy_to_redis(self, policies) : 

        # REDIS TRANSACTION ---------------------------------------------------
        p = self.r.pipeline()

        # avoid redundancy. Clearing the list
        p.delete(self.policies_key)

        # push the policies to redis
        p.rpush(self.policies_key, *policies)

        # update policy timestamp in Redis (notify others that policy has changed)
        p.set(self.policies_timestamp_key, int(time.time() * 1000))

        # execute the pipeline
        p.execute()
        # ---------------------------------------------------------------------
        logger.debug("Loaded Policy to Redis")


    def get_all_policies(self) : 
        """
            Returns list of policies as per Pycasbin Enforcer.
            This is a syncronized method. i.e when this is called,
                The enforcer automatically syncs with REDIS.
        """
        enforcer = self.get_enforcer(sync=True)
        model = enforcer.get_model()

        policies = []
        if "p" in model.model.keys() : 
            for key, ast in model.model["p"].items():
                for pvals in ast.policy : 
                    policies.append(key + ', ' + ', '.join(pvals))

        if "g" in model.model.keys() :
            for key, ast in model.model["g"].items():
                for pvals in ast.policy : 
                    policies.append(key + ', ' + ', '.join(pvals))
        return policies




    class PolicyUpdateFailure(Exception) : pass
    class S3PolicyUploadFailure(Exception) : pass
    class S3PolicyDownloadFailure(Exception) : pass
    class S3PolicyParseFailure(Exception) : pass
    

if __name__ == "__main__" : 
    mgr = PolicyManager(
        redis_endpoint = 'localhost:6379',
        policies_key = '__key__policies___k',
        policies_timestamp_key = '__key__timestamp_policies',
        policy_model_path = os.path.join(os.getcwd(), 'policy_model.conf'),
        s3_bucket = 'accounts.intrinzics.xyz',
        s3_policies_key = 'policies/internal_access_policy.csv',
        sync_interval=30
    )
