import unittest
import os,sys
import redis
from pprint import pprint
import time

# AWS STORAGE
import boto3
import botocore
s3_client = boto3.client('s3')

import logging
#logging.basicConfig(level=logging.DEBUG)
#logging.getLogger('boto3').setLevel(logging.CRITICAL)
#logging.getLogger('botocore').setLevel(logging.CRITICAL)
#logging.getLogger('s3transfer').setLevel(logging.CRITICAL)

sys.path.append(os.path.join(os.getcwd(), '../src'))
from policy import PolicyManager

class PolicyTest(unittest.TestCase) : 

    def setUp(self) : 

        # REDIS - CHECK AND FLUSH
        self.REDIS_ENDPOINT = 'localhost:6379'
        self.POLICIES_TIMESTAMP_KEY = '__key__stamp_policy_'
        self.REDIS_POLICIES_KEY = '__key__policy'
        self.RHOST, self.RPORT = self.REDIS_ENDPOINT.split(':')
        self.SYNC_INTERVAL = 30
        self.r = redis.Redis(self.RHOST, self.RPORT)
        try : self.r.ping()
        except :
            self.fail(f"Redis Server {self.redis_endpoint} not reachable")
        self.r.flushall()

        # S3
        self.TEST_S3_BUCKET = 'test.dev.general'
        #self.S3_POLICIES_KEY = 'policies/test_policies.csv'
        #try : head_obj = s3_client.head_object(Bucket=self.S3_BUCKET, Key=self.S3_POLICIES_KEY)
        #except : 
        #    self.fail("S3 error. Possible reasons \n1.Bucket Invalid\n2.Policy file missing\n3.Credentials Error")

        # PYCASBIN
        self.REST_POLICY_MODEL_PATH = os.path.join(os.getcwd(), 'testfiles', 'rest_policy_model.conf')
        assert os.path.exists(self.REST_POLICY_MODEL_PATH)

        # Initiate Policy Manager

    def testPolicyManagerInDistributedSetting(self):

        # Upload policies to S3
        s3_bucket = self.TEST_S3_BUCKET
        s3_policies_key = 'policies/test_policies.csv'
        policies = [
            "p, resourceA_GET_role, /resA/:entity/cat/, GET",
            "p, resourceB_GET_role, /resB/xyz/, GET",
            "p, resourceC_POST_role, /resC/, POST",
        ]
        with open('temp_policy.csv', 'w') as f :
            for p in policies : 
                f.write(p + '\n')
        s3_client.upload_file(Filename='temp_policy.csv', Bucket=s3_bucket, Key=s3_policies_key)


        # As long as all the policy manager have the same Params passed to them, they should
        #   eventually be in sync. (as determined by SYNC Interval

        # initiate 3 instances of Policy Manager
        sync_interval = 10  # hence all policy managers must be in sync after 10 seconds.
        params = {
            'redis_endpoint' : self.REDIS_ENDPOINT,
            'policies_key' : self.REDIS_POLICIES_KEY,
            'policies_timestamp_key' : self.POLICIES_TIMESTAMP_KEY,
            'policy_model_path' : self.REST_POLICY_MODEL_PATH,
            's3_bucket' : s3_bucket,
            's3_policies_key' : s3_policies_key,
            'sync_interval' : sync_interval
        }
        policy_mgr1 = PolicyManager(**params)
        policy_mgr2 = PolicyManager(**params)
        policy_mgr3 = PolicyManager(**params)

        # assert that they are different instances
        self.assertNotEquals(policy_mgr1, policy_mgr2)
        self.assertNotEquals(policy_mgr1, policy_mgr3)

        # assert that they all have the same policies at first
        self.assertSetEqual(set(policy_mgr1.get_all_policies()), set(policy_mgr2.get_all_policies()))
        self.assertSetEqual(set(policy_mgr1.get_all_policies()), set(policy_mgr3.get_all_policies()))

        # update policy_mgr1
        entity, path, method = 'user1', '/resA/apple/cat/', "GET"
        self.assertFalse(policy_mgr1.enforce(entity, path, method))     # initally not authorized
        self.assertFalse(policy_mgr2.enforce(entity, path, method))
        self.assertFalse(policy_mgr3.enforce(entity, path, method))
        redis_policy_timestamp_before_update = self.r.get(self.POLICIES_TIMESTAMP_KEY)
        
        # PROCEDURE to update policy in policy manager -----------------------
        policy_mgr1_enforcer = policy_mgr1.get_enforcer()
        policy_mgr1_enforcer.add_role_for_user(entity, 'resourceA_GET_role')
        policy_mgr1_enforcer.save_policy()
        policy_mgr1.save_policy_to_s3()
        redis_policy_timestamp_after_update = self.r.get(self.POLICIES_TIMESTAMP_KEY)
        self.assertTrue(policy_mgr1.enforce(entity,path,method))
        # ---------------------------------------------------------------------
        # policy update should update timestamp on redis
        self.assertNotEqual(redis_policy_timestamp_before_update, redis_policy_timestamp_after_update)

        # changes wont be reflected in other policy_mgr for <sync_interval> seconds
        self.assertFalse(policy_mgr2.enforce(entity, path, method))
        self.assertFalse(policy_mgr3.enforce(entity, path, method))
        time.sleep(sync_interval + 0.5)
        # after <sync interval> all policy managers should be in sync.
        self.assertTrue(policy_mgr2.enforce(entity, path, method))
        self.assertTrue(policy_mgr3.enforce(entity, path, method))


        # delete policies in S3
        s3_client.delete_object(Bucket=s3_bucket, Key=s3_policies_key)

        # delete temp_policy.csv
        os.remove('temp_policy.csv')



    def testPolicyManagerRESTAccessPolicies(self) : 
        # s3
        s3_bucket = self.TEST_S3_BUCKET
        s3_policies_key = 'policies/test_policies.csv'

        # Upload policies to S3
        # Ensure that policies are terminated with / at the end
        # Note that policies match minimal regex. so /xyz would also accept /xyzk
        #   by terminating with / we prevent possible errors.
        # However, /xyz/ would accept /xyz/sdlfk/asdflkj
        # See : https://casbin.org/docs/en/function
        policies = [
            "p, resourceA_GET_role, /resA/:entity/cat/, GET",
            "p, resourceB_GET_role, /resB/xyz/, GET",
            "p, resourceC_POST_role, /resC/, POST",
            "g, user1, resourceA_GET_role",
            "g, user3, resourceC_POST_role",
            "g, user4, resourceB_GET_role"
        ]
        with open('temp_policy.csv', 'w') as f :
            for p in policies : 
                f.write(p + '\n')
        s3_client.upload_file(Filename='temp_policy.csv', Bucket=s3_bucket, Key=s3_policies_key)

        policy_mgr = PolicyManager(
            redis_endpoint = self.REDIS_ENDPOINT,
            policies_key = self.REDIS_POLICIES_KEY,
            policies_timestamp_key = self.POLICIES_TIMESTAMP_KEY,
            policy_model_path = self.REST_POLICY_MODEL_PATH,
            s3_bucket = s3_bucket,
            s3_policies_key = s3_policies_key,
            sync_interval= self.SYNC_INTERVAL
        )

        # policies must obviously match (since that was the source)
        self.assertSetEqual(set(policies), set(policy_mgr.get_all_policies()))

        # use : https://casbin.org/editor/
        # Turns out that editor is useless. Better use local pycasbin module
        expected_response = {
            "user1, /resA/apple/cat/, GET"      : True,
            "user1, /resA/apple/cat/egg/, GET"  : False,  # since :used, must end with /cat/
            "user1, /resA/apple/egg/cat/, GET"  : False,  # cannot contain /in the middle (thats where it starts matching)
            "user1, /resA/appleyac/, GET"       : False,  # no trailing /cat/
            "user1, /resA/, GET"                : False,  # no entity specified
            "user1, /resA/applecat/, POST"      : False,  # POST not allowed
            "user5, /resA/applecat, GET"        : False,  # user5 not allowed
            "user4, /resB/xyz, POST"            : False,  # POST not allowed
            "user4, /resB/xyz/, GET"            : True,
            "user4, /resB/xyz, GET"             : False,  # no trailing slash
            "user4, /resB/xyzk, GET"            : False,  # xyzk not allowed
            "user1, /resB/xyz, GET"             : False,  # user1 not allowed
            "user4, /resC/, POST"               : False,  # user4 not allowed
            "user3, /resC/, POST"               : True,   
            "user3, /resC, POST"                : False,  # no trailing slash
            "user7, /resC/xyz/, POST"           : False,  # user7 not allowed
            "user7, /resC/xyz/, POST"           : False,  # user7 not allowed
            "user3, /resC/, GET"                : False,  # GET not allowed
        }
        for rules, expectedVal in expected_response.items() : 
            entity, path, method = rules.replace(' ','').split(',')
            if expectedVal is True :
                self.assertTrue(policy_mgr.enforce(entity, path, method))
            elif expectedVal is False :
                self.assertFalse(policy_mgr.enforce(entity, path, method))

        # delete policies in S3
        s3_client.delete_object(Bucket=s3_bucket, Key=s3_policies_key)

        # delete temp_policy.csv
        os.remove('temp_policy.csv')


    def testPolicyManagerWithMissingS3PolicyFile(self) : 
        # S3
        s3_bucket = self.TEST_S3_BUCKET

        # No policy file uploaded(only stated)
        s3_policies_key = 'no_policies_file_uploaded'

        with self.assertRaises(PolicyManager.S3PolicyDownloadFailure) :
            policy_mgr = PolicyManager(
                redis_endpoint = self.REDIS_ENDPOINT,
                policies_key = self.REDIS_POLICIES_KEY,
                policies_timestamp_key = self.POLICIES_TIMESTAMP_KEY,
                policy_model_path = self.REST_POLICY_MODEL_PATH,
                s3_bucket = s3_bucket,
                s3_policies_key = s3_policies_key,
                sync_interval= self.SYNC_INTERVAL
            )


    def tearDown(self) :
        self.r.flushall()
        pass


if __name__ == '__main__' : 
    loader = unittest.TestLoader()
    policyTestSuite = unittest.TestSuite()
    policyTestSuite.addTests(loader.loadTestsFromModule(PolicyTest()))
    unittest.TextTestRunner(verbosity=3).run(policyTestSuite)
