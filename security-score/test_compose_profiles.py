"""REQ-27/04/12: useful Compose declarations without evaluation or disclosure."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent / 'scripts'))
import score_compose as compose
from score_sources import Budget
from test_subscores import Invocation
from score_assessment import render
from score_style import Style


class ComposeProfiles(Invocation, unittest.TestCase):
    def profile(self, source, **extra):
        return compose.inspect({'compose.yaml': {'text': source, **extra}}, Budget(10))

    def properties(self, source):
        return {key: value['value'] for key, value in self.profile(source)['services'][0]['properties'].items()}

    def test_service_profiles_include_selected_settings_and_locations(self):
        source = '''services:
  web:
    image: registry.example/web@sha256:''' + 'a' * 64 + '''
    ports:
      - "127.0.0.1:8080:80"
      - target: 443
        published: "8443"
        host_ip: "0.0.0.0"
    user: "1000:1000"
    privileged: false
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    read_only: true
    volumes:
      - ./config:/etc/web:ro
      - type: bind
        source: /var/run/docker.sock
        target: /run/docker.sock
        read_only: true
    networks: [private]
    cpus: 0.5
    mem_limit: 256m
    pids_limit: 100
    healthcheck:
      test: ["CMD", "true"]
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "1.0"
'''
        props = self.properties(source)
        self.assertTrue(props['image']['immutable_digest'])
        self.assertEqual(props['ports'][0]['binding'], 'loopback')
        self.assertEqual(props['ports'][1]['binding'], 'all interfaces')
        self.assertEqual(props['ports'][1]['published'], '8443')
        self.assertEqual(props['user'], '1000:1000')
        self.assertEqual(props['cap_drop'], ['ALL'])
        self.assertTrue(props['volumes'][0]['read_only'])
        self.assertTrue(props['volumes'][1]['docker_socket'])
        self.assertEqual(props['healthcheck'], 'declared; command omitted')
        self.assertEqual(props['deploy'], {'memory': '512M', 'cpus': '1.0'})
        _, result = self.invoke({'compose.yaml': source})
        self.assertEqual(result['architecture']['compose']['services'][0]['properties']['image']['line'], 3)
        output = render(result, details=True, style=Style('never', 'never'))
        block = output.split('Deployment & operations', 1)[1]
        self.assertIn('Compose service profiles:', block)
        self.assertIn('    compose.yaml', block)
        self.assertIn('      web (line 2):', block)
        self.assertIn('loopback', block)
        self.assertIn('Docker socket', block)

    def test_services_and_overrides_stay_separate_and_do_not_award_points(self):
        files = {
            'compose.yaml': 'services:\n  app:\n    image: web:1\n    read_only: true\n  db:\n    image: db:2\n',
            'compose.override.yaml': 'services:\n  app:\n    read_only: false\n',
        }
        status, result = self.invoke(files)
        self.assertEqual(status, 2)
        self.assertTrue(all(row['score'] is None for row in result['subscores']))
        rows = result['architecture']['compose']['services']
        self.assertEqual(len(rows), 3)
        values = {row['file']: row['properties']['read_only']['value'] for row in rows if row['service'] == 'app'}
        self.assertEqual(values, {'compose.override.yaml': False, 'compose.yaml': True})
        self.assertIn('override order', result['architecture']['compose']['interpretation'])
        self.assertNotIn('privileged', rows[0]['properties'])

    def test_dynamic_duplicate_unsupported_fields_and_inheritance_stay_unresolved(self):
        source = '''include: other.yml
services:
  app:
    <<: *defaults
    extends: base
    image: ${IMAGE:-web:latest}
    privileged: false
    privileged: true
    read_only: !override true
    ports: ["${PORT}:80"]
    networks: *networks
'''
        profile = self.profile(source)
        self.assertTrue(profile['gaps'])
        row = profile['services'][0]
        self.assertTrue(row['unresolved'])
        props = {key: item['value'] for key, item in row['properties'].items()}
        for key in ('image', 'privileged', 'read_only', 'networks'):
            self.assertEqual(props[key], 'unresolved', key)
        self.assertEqual(props['ports'], 'unresolved')

    def test_tags_commands_environment_and_unselected_fields_are_never_exposed_or_executed(self):
        source = '''services:
  app:
    image: "https://user:PRIVATE_VALUE@example.test/web?token=PRIVATE_VALUE"
    environment:
      PASSWORD: PRIVATE_VALUE
    labels:
      token: PRIVATE_VALUE
    read_only: !!python/object/apply:os.system ["touch /tmp/compose-executed"]
    command: !!python/object/apply:os.system ["touch /tmp/compose-executed"]
    healthcheck:
      test: ["CMD-SHELL", "echo PRIVATE_VALUE"]
    volumes:
      - type: bind
        source: "https://user:PRIVATE_VALUE@example.test/"
        target: /tmp
'''
        encoded = json.dumps(self.profile(source))
        self.assertNotIn('PRIVATE_VALUE', encoded)
        self.assertNotIn('os.system', encoded)
        self.assertNotIn('CMD-SHELL', encoded)
        self.assertIn('unresolved', encoded)
        self.assertFalse(Path('/tmp/compose-executed').exists())

    def test_aliases_block_scalars_comments_and_duplicate_services_do_not_create_facts(self):
        for source in (
            'services:\n  app: *shared\n',
            'services:\n  app:\n    image: web\n  app:\n    image: other\n',
            'services: &services\n  app:\n    image: web\n',
        ):
            profile = self.profile(source)
            self.assertTrue(profile['gaps'] or profile['services'][0]['unresolved'])
        profile = self.profile('x-example: |\n  services:\n    fake:\n      privileged: true\n# services:\nservices:\n  real:\n    image: web # comment\n')
        self.assertEqual([row['service'] for row in profile['services']], ['real'])
        self.assertEqual(profile['services'][0]['properties']['image']['value']['reference'], 'web')

    def test_malformed_types_never_crash_or_claim_supported_values(self):
        for field, value in (
            ('image', '["foo"]'), ('ports', '[{"target": 80, "protocol": []}]'),
            ('volumes', '[{"type": [], "target": "/tmp"}]'),
            ('volumes', '[{"type": "bind", "source": [], "target": "/tmp"}]'),
            ('privileged', '{}'), ('networks', 'true'),
            ('deploy', '{"resources": {"limits": []}}'), ('user', '!unsafe user'),
            ('healthcheck', '{"disable": "false"}'),
        ):
            with self.subTest(field=field):
                props = self.properties(f'services:\n  app:\n    {field}: {value}\n')
                self.assertIn('unresolved', json.dumps(props[field]))

    def test_incomplete_sources_and_profile_limits_are_visible(self):
        self.assertTrue(self.profile('services:\n  app:\n', fragment=True)['gaps'])
        profile = self.profile('services:\n' + ''.join(f'  svc{i}:\n    image: web\n' for i in range(101)))
        self.assertEqual(len(profile['services']), 100)
        self.assertIn('limit', profile['gaps'][0]['reason'])
        profile = self.profile('services:\n' + '\n' * 20000)
        self.assertIn('limit', profile['gaps'][0]['reason'])
        profile = compose.inspect({}, Budget(10), ['compose.yaml'])
        self.assertIn('unavailable', profile['gaps'][0]['reason'])

    def test_short_and_long_ports_mounts_and_disabled_healthchecks(self):
        for value in ('3000:3000', '127.0.0.1:3000:3000', '[::1]:3000:3000', '80', '3000:3000/udp'):
            with self.subTest(value=value):
                self.assertIsInstance(compose.port(value), dict)
        for value in ('70000:80', '${HOST}:80:80', 'http://user:pass@host', {'target': 80, 'host_ip': []}):
            self.assertEqual(compose.port(value), 'unresolved')
        self.assertTrue(compose.mount('/host:/target:ro,z')['read_only'])
        self.assertEqual(compose.selected('healthcheck', {'test': ['NONE']}), 'disabled')
        self.assertEqual(compose.selected('healthcheck', {'disable': True}), 'disabled')

    def test_ambiguous_flow_objects_and_bad_indentation_stay_unresolved(self):
        props = self.properties('services:\n  web:\n    ports: [{"target": 80, "host_ip": "0.0.0.0", "host_ip": "127.0.0.1"}]\n')
        self.assertEqual(props['ports'], 'unresolved')
        profile = self.profile('services:\n  web:\n    image: web\n   privileged: false\n')
        self.assertTrue(profile['gaps'])
        self.assertEqual(profile['services'], [])

    def test_profile_does_not_depend_on_details_or_change_the_score(self):
        files = {'compose.yaml': 'services:\n  web:\n    image: web:1\n    read_only: true\n'}
        plain_status, plain = self.invoke(files)
        detail_status, details = self.invoke(files, '--details')
        self.assertEqual(plain_status, detail_status)
        for key in ('overall', 'subscores', 'findings'):
            self.assertEqual(plain[key], details[key])
        self.assertEqual(plain['architecture']['compose'], details['architecture']['compose'])

    def test_details_omit_missing_fields_and_empty_services_without_losing_structured_evidence(self):
        source = ('services:\n  sut:\n    build: .\n    depends_on: [app]\n'
                  '  app:\n    image: bkimminich/juice-shop:latest\n')
        _, result = self.invoke({'docker-compose.test.yml': source})
        before = json.dumps(result, sort_keys=True)
        output = render(result, details=True, style=Style('never', 'never'))
        block = output.split('Compose service profiles:', 1)[1].split('Coverage', 1)[0]
        self.assertNotIn('sut (', block)
        self.assertIn('    docker-compose.test.yml', block)
        self.assertIn('      app (line 5):', block)
        self.assertIn('bkimminich/juice-shop:latest', block)
        for label in ('Ports', 'Networks', 'Privileges', 'Filesystem', 'Operations'):
            self.assertNotIn(label, block)
        self.assertEqual([row['service'] for row in result['architecture']['compose']['services']], ['sut', 'app'])
        self.assertEqual(before, json.dumps(result, sort_keys=True))

    def test_empty_profiles_do_not_add_an_empty_heading(self):
        _, result = self.invoke({'compose.yaml': 'services:\n  sut:\n    build: .\n'})
        output = render(result, details=True, style=Style('never', 'never'))
        self.assertNotIn('Compose service profiles:', output)
        self.assertIn('Declared deployment targets: Docker Compose', output)
        self.assertEqual(len(result['architecture']['compose']['services']), 1)

    def test_file_grouping_keeps_services_settings_and_source_lines(self):
        files = {
            'compose.yaml': ('services:\n  web:\n    image: example/web:1\n'
                             '    ports: ["127.0.0.1:8080:80"]\n'
                             '    volumes: ["./config:/etc/web:ro"]\n'
                             '    networks: [private]\n'
                             '    restart: unless-stopped\n'
                             '  db:\n    image: example/db:2\n'),
            'infrastructure/compose.yaml': 'services:\n  web:\n    image: example/other:3\n',
        }
        _, result = self.invoke(files)
        before = json.dumps(result, sort_keys=True)
        output = render(result, details=True)
        first = output.split('    compose.yaml\n', 1)[1].split('    infrastructure/compose.yaml\n', 1)[0]
        second = output.split('    infrastructure/compose.yaml\n', 1)[1]
        self.assertIn('      web (line 2):', first)
        self.assertIn('      db (line 8):', first)
        self.assertIn('      web (line 2):', second)
        normalized = ' '.join(first.split())
        for setting in ('image: example/web:1 (digest not declared) (line 3)',
                        'ports: 127.0.0.1:8080 -> 80/tcp (loopback) (line 4)',
                        'volumes: bind ./config -> /etc/web (read-only) (line 5)',
                        'networks: private (line 6)',
                        'restart: unless-stopped (line 7)',
                        'image: example/db:2 (digest not declared) (line 9)'):
            self.assertIn(setting, normalized)
        self.assertIn('image: example/other:3', second)
        self.assertIn('override order', second)
        self.assertEqual(before, json.dumps(result, sort_keys=True))

    def test_group_headings_never_emit_repository_control_characters(self):
        _, result = self.invoke({'compose.yaml': 'services:\n  web:\n    image: example/web:1\n'})
        service = result['architecture']['compose']['services'][0]
        service['file'] = 'bad\x1b[2J\ncompose.yaml'
        service['service'] = 'web\x1b]0;changed\x07'
        output = render(result, details=True)
        self.assertNotRegex(output, r'[\x00-\x09\x0b-\x1f\x7f-\x9f]')
        self.assertIn('    bad?[2J?compose.yaml', output)
        self.assertIn('      web?]0;changed? (line 2):', output)

    def test_unresolved_fields_and_parser_gaps_remain_visible(self):
        for source, expected in (
            ('services:\n  app:\n    image: ${IMAGE}\n', 'image: unresolved'),
            ('services:\n  app: *shared\n', 'service mapping, alias or anchor'),
            ('services: !unsupported {}\n', 'services mapping is missing'),
        ):
            with self.subTest(expected=expected):
                _, result = self.invoke({'compose.yaml': source})
                output = render(result, details=True, style=Style('never', 'never'))
                self.assertIn('Compose service profiles:', output)
                self.assertIn(expected, output)
                self.assertNotIn('Ports           not declared', output)

    def test_empty_services_do_not_consume_the_text_limit(self):
        source = 'services:\n' + ''.join(f'  empty{i}:\n    build: .\n' for i in range(4))
        source += ''.join(f'  app{i}:\n    image: web:1\n' for i in range(4))
        _, result = self.invoke({'compose.yaml': source})
        output = render(result, details=True, style=Style('never', 'never'))
        self.assertNotIn('empty0 (', output)
        self.assertIn('app0 (', output)
        self.assertIn('app2 (', output)
        self.assertNotIn('app3 (', output)
        self.assertIn('+1 service declarations in JSON/YAML', output)
        self.assertEqual(len(result['architecture']['compose']['services']), 8)

    def test_details_limit_keeps_all_structured_services(self):
        source = 'services:\n' + ''.join(f'  svc{i}:\n    image: web\n' for i in range(5))
        _, result = self.invoke({'compose.yaml': source})
        self.assertEqual(len(result['architecture']['compose']['services']), 5)
        output = render(result, details=True, style=Style('never', 'never'))
        self.assertIn('+2 service declarations in JSON/YAML', output)
        self.assertNotIn('Networks        not declared', output)


if __name__ == '__main__':
    unittest.main()
