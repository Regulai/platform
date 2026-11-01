"""Focused guards for the second UX candidate; no Docker or service mutations."""
import copy
import unittest
from unittest.mock import Mock, patch

import p1_skills_ux_auto_update as update
import p1_skills_ux_finish_update as coordinated
import p1_skills_ux_update_remote as ux


class AutoUpdateGuards(unittest.TestCase):
    def setUp(self):
        self.original = {'Id':'original','Image':'base','Config':{'Image':'base',
            'Hostname':'old','Domainname':'','Labels':{'regulai.skills_ux':'old'}},
            'HostConfig':{'OomKillDisable':None,'RestartPolicy':{'Name':'no'}},
            'Mounts':[{'Destination':'/b','Source':'/two','RW':False},{'Destination':'/a','Source':'/one','RW':False}]}
        self.previous = {'candidate_id':'new','image_id':'sha256:candidate'}
        self.candidate = copy.deepcopy(self.original)
        self.candidate.update(Id='new',Image='sha256:candidate',Name='/'+update.WEB+'-candidate-'+update.IDENTITY,
            State={'Running':False,'Status':'created'})
        self.candidate['Config'].update(Image='sha256:candidate',Hostname='new')
        self.candidate['Config']['Labels']['regulai.skills_ux']=update.IDENTITY
        self.candidate['HostConfig']['OomKillDisable']=False
        self.candidate['Mounts'].reverse()
        self.inspect=Mock(return_value=self.candidate)
        self.context=patch.multiple(update,create=True,helper={'inspect':self.inspect},
            co=coordinated.__dict__,ux=ux.__dict__)
        self.context.start();self.addCleanup(self.context.stop)

    def test_candidate_permits_only_docker_default_oom_and_mount_order(self):
        self.assertEqual(update.candidate_check(self.previous,self.original)['Id'],'new')

    def test_candidate_rejects_wrong_id_name_image_or_state(self):
        for key,value in [('Id','foreign'),('Image','foreign'),('Name','/foreign'),('State',{'Running':True,'Status':'running'})]:
            with self.subTest(key=key):
                bad=copy.deepcopy(self.candidate);bad[key]=value;self.inspect.return_value=bad
                with self.assertRaises(RuntimeError):update.candidate_check(self.previous,self.original)

    def test_candidate_rejects_every_material_config_change(self):
        changes=[('Config','Image','unexpected'),('HostConfig','OomKillDisable',True),
            ('HostConfig','OomKillDisable',0),('HostConfig','NewSetting',False)]
        for section,key,value in changes:
            with self.subTest(section=section,key=key,value=value):
                bad=copy.deepcopy(self.candidate);bad[section][key]=value;self.inspect.return_value=bad
                with self.assertRaises(RuntimeError):update.candidate_check(self.previous,self.original)

    def test_candidate_rejects_changed_mount(self):
        self.candidate['Mounts'][0]['RW']=True
        with self.assertRaises(RuntimeError):update.candidate_check(self.previous,self.original)

    def test_identity_is_canonical_and_retains_true_and_mount_changes(self):
        baseline=update.identity(self.original); equivalent=copy.deepcopy(self.original)
        equivalent['HostConfig']['OomKillDisable']=False;equivalent['Mounts'].reverse()
        self.assertEqual(baseline,update.identity(equivalent))
        equivalent['HostConfig']['OomKillDisable']=True;self.assertNotEqual(baseline,update.identity(equivalent))

    def test_prepare_requires_exact_seven_paths_before_any_remote_operation(self):
        self.assertEqual(len(update.FILES),7)
        self.assertIn('regulai/front/agents/skill_context.py',update.FILES)
        for paths in ([],list(update.FILES)[:-1],[*update.FILES,'regulai/front/agents/worker.py']):
            with self.subTest(paths=paths),patch.object(update,'REQUEST',{'payload':{'files':paths}},create=True):
                with self.assertRaisesRegex(RuntimeError,'exact_seven'):update.prepare()
        self.inspect.assert_not_called()

    def test_current_base_requires_exact_ids_image_and_running(self):
        rows={update.WEB:{'Image':update.BASE_IMAGE,'State':{'Running':True}},
            update.WORKER:{'State':{'Running':True}},update.PG:{'State':{'Running':True}}}
        with patch.dict(coordinated.__dict__,{'named':Mock(side_effect=lambda n,i:rows[n])}):
            update.original_rows()
            self.assertEqual(coordinated.named.call_args_list[0].args,(update.WEB,update.BASE_WEB))
            rows[update.WEB]['Image']='foreign'
            with self.assertRaises(RuntimeError):update.original_rows()
            rows[update.WEB]['Image']=update.BASE_IMAGE;rows[update.WORKER]['State']['Running']=False
            with self.assertRaises(RuntimeError):update.original_rows()


if __name__=='__main__':
    unittest.main(verbosity=2)
