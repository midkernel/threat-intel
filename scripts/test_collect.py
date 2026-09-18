#!/usr/bin/env python3
"""Offline behavioral checks for evidence retention, failure accounting and resume."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from collect import Archive, cna, collect_source, epss, ghsa, osv, parse_epss, KEV_MIRROR, observed_cves
from index import feed_items, json_items, source_details

AT = "2026-09-18T11:00:00Z"
CSV = b"#model_version:v2025.03.14,score_date:2026-09-17T12:00:00Z\ncve,epss,percentile\nCVE-2026-1000,0.1,0.2\nCVE-2026-1001,0.5,0.8\nCVE-2026-1002,1,1\n"

class EvidenceTests(unittest.TestCase):
    def test_native_xml_talos_and_content_retained(self):
        kind, rows = feed_items(b'<rss><channel><item><report_id>TALOS-2026-1234</report_id><title>Advisory</title><date>September 17, 2026</date><description>Native summary</description><chain>Solana</chain></item></channel></rss>')
        self.assertEqual(rows[0]['id'], 'TALOS-2026-1234')
        self.assertIsNone(rows[0]['url'])
        self.assertEqual(rows[0]['raw']['fields']['chain'][0]['text'], 'Solana')
        self.assertEqual(rows[0]['summary'], 'Native summary')

    def test_structured_versions_chain_withdrawal_and_nullable_dates(self):
        rows = json_items([{'uid':'SOL-2026-1','name':'Compiler bug','introduced':'0.8.0','fixed':'0.8.1','conditions':{'optimizer':True}}])
        self.assertIsNone(rows[0]['published_at'])
        self.assertEqual(rows[0]['raw']['conditions'], {'optimizer':True})
        rows = json_items([{'name':'Protocol','date':None,'chain':['Solana'],'defillamaId':'123','technique':'Key compromise'}])
        self.assertIsNone(rows[0]['id'])
        self.assertIsNone(rows[0]['published_at'])
        self.assertEqual(rows[0]['raw']['chain'], ['Solana'])
        rows = json_items({'records':[{'id':'GHSA-aaaa-bbbb-cccc','modified':AT,'withdrawn':AT,'aliases':['CVE-2026-1234'],'affected':[{'package':{'ecosystem':'npm','name':'demo'}}]}]})
        self.assertEqual(rows[0]['withdrawn_at'], AT)
        self.assertEqual(rows[0]['aliases'], ['CVE-2026-1234'])

    def test_bad_parse_and_partial_rows_are_never_confirmed_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'body.json'; path.write_text('{')
            items, info = source_details({'format':'json'}, {'status':200}, path)
            self.assertEqual(info['status']['parse'], 'error')
            self.assertEqual(info['status']['completeness'], 'unknown')
            path.write_text(json.dumps([{'uid':'SOL-1','name':'Bug'}, None]))
            items, info = source_details({'format':'json'}, {'status':200}, path)
            self.assertEqual(info['status']['rejected_count'], 1)
            self.assertEqual(info['status']['completeness'], 'partial')
            path.write_text(json.dumps({'count': 3, 'vulnerabilities': [{'cveID':'CVE-2026-1'}]}))
            _, info = source_details({'format':'json'}, {'status':200}, path)
            self.assertIn('catalog_count_mismatch', info['status']['reasons'])
            self.assertEqual(info['status']['completeness'], 'partial')

class CollectionTests(unittest.TestCase):
    def test_full_epss_preserves_sidecar_and_stock_date_not_fetch_day(self):
        raw = gzip.compress(CSV)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'first-epss'; output.mkdir()
            payload = epss(Archive(output, lambda url:(raw,200,{})))
            self.assertEqual(payload['statistics']['scored_total'],3)
            self.assertEqual(payload['statistics']['high_count'],2)
            self.assertEqual(payload['statistics']['score_date'],'2026-09-17')
            self.assertEqual((Path(tmp)/payload['snapshot']['path']).read_bytes(),raw)
            self.assertEqual(payload['records'],[])
            self.assertEqual(sum(x['count'] for x in payload['statistics']['distribution']),3)
        for malformed in [CSV.replace(b'0.5',b'nan'), CSV.replace(b'0.5',b'1.1'), CSV.replace(b'CVE-2026-1001',b'CVE-2026-1000')]:
            with self.assertRaises(ValueError): parse_epss(gzip.compress(malformed))

    def test_ghsa_budget_resume_and_withdrawals(self):
        calls=[]
        def fetch(url):
            calls.append(url)
            second = 'after=cursor' in url
            row={'ghsa_id':'GHSA-2' if second else 'GHSA-1', 'withdrawn_at':AT if second else None}
            return json.dumps([row]).encode(),200,{} if second else {'link':'<https://api.github.com/advisories?after=cursor>; rel="next"'}
        with tempfile.TemporaryDirectory() as tmp:
            state={}
            first=ghsa(Archive(Path(tmp)/'a',fetch),state,'malware',at=AT,max_pages=1)
            self.assertTrue(first['checkpoint']['pending'])
            self.assertIsNone(first['checkpoint']['through'])
            second=ghsa(Archive(Path(tmp)/'b',fetch),state,'malware',at=AT,max_pages=1)
            self.assertEqual(second['records'][0]['withdrawn_at'],AT)
            self.assertTrue(second['checkpoint']['cycle_complete'])
            self.assertFalse(second['checkpoint']['historical_corpus_complete'])
            self.assertIn('type=malware',calls[0])
            self.assertEqual(calls[1],'https://api.github.com/advisories?after=cursor')

    def test_ghsa_error_keeps_failed_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            state={}
            def fail(url): raise ValueError('HTTP 429')
            result=ghsa(Archive(Path(tmp),fail),state,'reviewed',at=AT)
            self.assertTrue(state['next_url'])
            self.assertIsNone(state.get('through'))
            self.assertIn('collection_error',result['status']['reasons'])

    def test_osv_resume_prioritizes_new_changes_and_retries_failed_versions(self):
        listing=b'2026-09-17T12:00:00Z,PYSEC-1\n2026-09-17T11:00:00Z,GHSA-2\n2020-01-01T00:00:00Z,OLD\n'
        calls=[]
        fail_record=[False]
        def fetch(url):
            calls.append(url)
            if url.endswith('modified_id.csv'): return listing,200,{}
            if fail_record[0]: raise ValueError('HTTP 503')
            return json.dumps({'id':url.rsplit('/',1)[-1][:-5],'modified':'2026-09-18T13:00:00Z','withdrawn':AT}).encode(),200,{}
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); state={}
            first=osv(Archive(directory/'a',fetch),state,directory,at=AT,max_records=1,ecosystems=('PyPI',))
            self.assertTrue(first['checkpoint']['pending'])
            self.assertEqual(len(state['processed']),1)
            fail_record[0]=True
            failed=osv(Archive(directory/'b',fetch),state,directory,at=AT,max_records=1,ecosystems=('PyPI',))
            self.assertIn('collection_error',failed['status']['reasons'])
            self.assertEqual(len(state['processed']),1)
            fail_record[0]=False
            last=osv(Archive(directory/'c',fetch),state,directory,at=AT,max_records=1,ecosystems=('PyPI',))
            self.assertTrue(last['checkpoint']['cycle_complete'])
            self.assertEqual(last['records'][0]['withdrawn'],AT)
            self.assertEqual(state['through'],AT)
            # A changed source version must be emitted again, including withdrawals.
            listing=b'2026-09-18T12:00:00Z,PYSEC-1\n'
            changed=osv(Archive(directory/'d',fetch),state,directory,at=AT,max_records=1,ecosystems=('PyPI',))
            self.assertEqual(len(changed['records']),1)
            self.assertFalse(changed['checkpoint']['historical_corpus_complete'])

    def test_osv_stale_blob_cannot_advance_version_checkpoint(self):
        def fetch(url):
            if url.endswith('modified_id.csv'):
                return b'2026-09-18T12:00:00Z,PYSEC-1\n',200,{}
            return json.dumps({'id':'PYSEC-1','modified':'2026-09-17T12:00:00Z'}).encode(),200,{}
        with tempfile.TemporaryDirectory() as tmp:
            state={}
            result=osv(Archive(Path(tmp),fetch),state,Path(tmp),at=AT,max_records=1,ecosystems=('PyPI',))
            self.assertEqual(state['processed'],{})
            self.assertFalse(result['checkpoint']['cycle_complete'])
            self.assertIn('older than its manifest',result['checkpoint']['error'])

    def test_official_kev_mirror_preserves_source_identity_and_explicit_provenance(self):
        raw=json.dumps({'count':1,'catalogVersion':'2026.09.18','vulnerabilities':[{'cveID':'CVE-2026-1234'}]}).encode()
        def fetch(url):
            if url != KEV_MIRROR: raise ValueError('primary HTTP 403')
            return raw,200,{}
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp); state=out/'state'; state.mkdir()
            source={'id':'cisa-kev','url':'https://example.test/kev','format':'json'}
            self.assertTrue(collect_source(source,out,state,fetch=fetch,at=AT))
            meta=json.loads((out/'cisa-kev/meta.json').read_text())
            self.assertEqual(meta['provenance']['effective_url'],KEV_MIRROR)
            self.assertTrue(meta['provenance']['fallback_used'])
            self.assertEqual(meta['provenance']['attempts'][0]['outcome'],'error')
            _, info=source_details(source,meta,out/'cisa-kev/body.json')
            self.assertEqual(info['status']['completeness'],'complete')
            self.assertEqual(info['provenance']['primary_url'],source['url'])

    def test_cna_scope_budget_cache_refresh_and_rejected_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp); directory=out/'cisa-kev'; directory.mkdir()
            (directory/'meta.json').write_text(json.dumps({'status':200}))
            (directory/'body.json').write_text(json.dumps({'vulnerabilities':[{'cveID':'CVE-2026-1234'},{'cveID':'CVE-2026-5678'}]}))
            calls=[]
            rejected=[False]
            def fetch(url):
                calls.append(url)
                identifier=url.rsplit('/',1)[-1][:-5]
                return json.dumps({'dataVersion':'5.1','cveMetadata':{'cveId':identifier,'state':'REJECTED' if rejected[0] else 'PUBLISHED','dateUpdated':AT},
                  'containers':{'cna':{'title':'Native CNA title','affected':[{'vendor':'Vendor','product':'Product','versions':[{'version':'1','status':'affected'}]}],
                  'problemTypes':[{'descriptions':[{'cweId':'CWE-79'}]}]}}}).encode(),200,{}
            state={}
            first=cna(Archive(out/'first',fetch),state,out,at=AT,max_records=1)
            self.assertEqual(len(first['records']),1)
            self.assertEqual(first['checkpoint']['pending_count'],1)
            self.assertIn('/2026/1xxx/CVE-2026-1234.json',calls[0])
            second=cna(Archive(out/'second',fetch),state,out,at=AT,max_records=1)
            self.assertEqual(second['records'][0]['cveMetadata']['cveId'],'CVE-2026-5678')
            cached=cna(Archive(out/'cached',fetch),state,out,at=AT,max_records=1)
            self.assertEqual(cached['records'],[])
            self.assertEqual(len(calls),2)
            rejected[0]=True
            changed=cna(Archive(out/'changed',fetch),state,out,at='2026-09-20T11:00:00Z',max_records=2)
            self.assertEqual(changed['records'][0]['cveMetadata']['state'],'REJECTED')
            item=json_items(changed)[0]
            self.assertEqual(item['id'],'CVE-2026-1234')
            self.assertIsNone(item['published_at'])
            self.assertIsNone(item['withdrawn_at'])
            self.assertEqual(item['raw']['containers']['cna']['problemTypes'][0]['descriptions'][0]['cweId'],'CWE-79')
            self.assertFalse(changed['checkpoint']['historical_corpus_complete'])

    def test_cna_fetch_failure_is_pending_without_fabricated_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            state={'targets':{'CVE-2026-1234':{'first_seen':AT,'origins':['cisa-kev']}}}
            def fail(url): raise ValueError('HTTP 404')
            result=cna(Archive(out,fail),state,out,at=AT,max_records=1)
            self.assertEqual(result['records'],[])
            self.assertEqual(result['checkpoint']['failed_identifiers'],1)
            self.assertFalse(result['checkpoint']['cycle_complete'])
            self.assertNotIn('sha256',state['targets']['CVE-2026-1234'])

if __name__ == '__main__': unittest.main()
