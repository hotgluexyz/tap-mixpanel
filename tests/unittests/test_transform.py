from unittest import TestCase

from tap_mixpanel.transform import denest_properties


class TestTransform(TestCase):
    def test_denest_properties_snakecase(self):
        record = {'$properties': {'key 1': 'value_1', 'Key # 2 > KEY 3': 'value_2'}}
        expected_record = {'key_1': 'value_1', 'key_2_key_3': 'value_2'}
        new_record = denest_properties(record, '$properties', denest_properties_snakecase=True)
        assert new_record == expected_record
