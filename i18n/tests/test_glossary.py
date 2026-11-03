import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

from translation_glossary import check


class NginxForbiddenRuleTest(unittest.TestCase):
    def test_lowercase_command_name_is_allowed(self):
        result = check(
            'en',
            '已跳过安装 nginx, 保留现有 nginx 不卸载',
            'Already skipped installing nginx, keeping the existing nginx without uninstalling.',
        )
        self.assertEqual(result['forbidden'], [])
        self.assertEqual(result['errors'], [])

    def test_brand_source_rejects_lowercase_target(self):
        result = check('en', 'Nginx 配置', 'nginx configuration')
        self.assertIn('nginx', result['forbidden'])
        self.assertTrue(result['errors'])

    def test_all_caps_nginx_is_always_rejected(self):
        result = check('en', 'Nginx 配置', 'NGINX configuration')
        self.assertIn('NGINX', result['forbidden'])
        self.assertTrue(result['errors'])

    def test_brand_source_accepts_brand_target(self):
        result = check('en', 'Nginx 配置', 'Nginx configuration')
        self.assertEqual(result['forbidden'], [])
        self.assertEqual(result['errors'], [])

    def test_russian_genitive_inflection_is_allowed(self):
        result = check(
            'ru',
            '无传输层加密的后端入站监听地址',
            'Адрес входящего прослушивания бэкенда без шифрования транспортного уровня',
        )
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['hit_rate'], 1.0)


if __name__ == '__main__':
    unittest.main()
