// Runs only in the new, isolated local E2B sandbox. No provider or network calls.
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const assert = require('node:assert/strict');
const work = '/workspace/work';
const root = '/skills/design-taste-frontend/scripts/';
fs.mkdirSync(`${work}/home`, {recursive:true});
fs.writeFileSync(`${work}/clean.html`, '<!doctype html><html lang="es"><meta charset="utf-8"><title>Ensayo local</title><main><h1>Reserva tu mesa</h1><p>Abierto de lunes a viernes.</p><a href="mailto:fixture@example.invalid">Escribir al restaurante</a></main></html>');
fs.writeFileSync(`${work}/banned.html`, '<html><style>body {background:linear-gradient(red,blue)}</style><body><h1>Lorem ipsum</h1></body></html>');
const checks=[];
function child(script,args,expected) {
  const result=spawnSync(process.execPath,[root+script,...args],{cwd:work,encoding:'utf8',timeout:15000,maxBuffer:500000,
    env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:`${work}/home`,TASTE_SKILL_HISTORY:`${work}/history.json`,
      NODE_OPTIONS:process.env.NODE_OPTIONS}});
  assert.equal(result.error,undefined);
  assert.equal(result.status,expected,result.stderr);
  return result.stdout;
}
assert.equal(process.version,'v24.21.0');
assert.deepEqual(Object.keys(os.networkInterfaces()).filter(key=>key!=='lo'),[]);
checks.push('network_none');
assert.throws(()=>fs.writeFileSync(root+'mutation-denied','x'),/EROFS|EACCES/);
assert.throws(()=>fs.writeFileSync('/skills/parent-mutation-denied','x'),/EROFS|EACCES/);
checks.push('skill_and_parent_readonly');
const args=['--sector','restaurant','--brief','A synthetic restaurant in Madrid with 24 seats',
  '--sections','intro,contact,footer','--seed','20261016'];
const options=child('draw.mjs',[...args,'--options','3'],0);
assert.equal((options.match(/^## `/gm)||[]).length,3);
assert.equal(fs.existsSync(`${work}/.taste-skill/direction.json`),false);
checks.push('three_options_no_write');
const output=child('draw.mjs',args,0);
const sheet=JSON.parse(fs.readFileSync(`${work}/.taste-skill/direction.json`));
assert.equal(sheet.seed,20261016);
assert.equal(sheet.sections.length,3);
assert.ok(sheet.hero.id&&sheet.type.id&&sheet.palette.id&&sheet.direction.id);
assert.ok(output.includes(sheet.direction.name));
assert.equal(JSON.parse(fs.readFileSync(`${work}/history.json`)).length,1);
checks.push('full_direction_and_scoped_history');
assert.equal(child('draw.mjs',['--show'],0),output);
checks.push('show_replays_saved_direction');
const clean=JSON.parse(child('lint.mjs',['clean.html','--json'],0));
assert.equal(clean.files,1);
assert.equal(clean.findings.filter(value=>value.level==='FAIL').length,0);
checks.push('clean_source_accepted');
const banned=JSON.parse(child('lint.mjs',['banned.html','--json'],1));
assert.ok(banned.findings.some(value=>value.id==='gradient'));
assert.ok(banned.findings.some(value=>value.id==='lorem'));
checks.push('banned_patterns_rejected');
console.log(JSON.stringify({all_passed:true,node:process.version,checks,
  skill_executed:['draw.mjs','lint.mjs'],other_scripts_executed:[],provider_requests:0}));
