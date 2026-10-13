import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
mkdirSync('../assets', {recursive:true});
await build({entryPoints:['src/entry.tsx'], bundle:true, minify:true, jsx:'automatic', format:'iife', outfile:'../assets/charts.js', alias:{'@':path.resolve('vendor/bklit')}, define:{'process.env.NODE_ENV':'"production"'}, legalComments:'eof', metafile:true}).then(r => writeFileSync('build-manifest.json',JSON.stringify({inputs:Object.keys(r.metafile.inputs),outputs:r.metafile.outputs},null,2)));
execFileSync(process.execPath,['node_modules/@tailwindcss/cli/dist/index.mjs','-i','src/chart-utilities.css','-o','../assets/charts.css','--minify'],{stdio:'inherit'});
// MIT attribution must accompany redistributed Bklit sources and bundle.
writeFileSync('../assets/BKLIT-LICENSE.txt',readFileSync('vendor/bklit/LICENSE'));
const inputs=JSON.parse(readFileSync('build-manifest.json')).inputs;
const packages=new Set(inputs.filter(p=>p.startsWith('node_modules/')).map(p=>p.startsWith('node_modules/@')?p.split('/').slice(0,3).join('/'):p.split('/').slice(0,2).join('/')));
let notices='PromptShield isolated research chart bundle\nBklit chart components: MIT, Copyright (c) 2026 uixmat\n'+readFileSync('vendor/bklit/LICENSE','utf8')+'\n';
for(const dir of [...packages].sort()){
 const pkg=JSON.parse(readFileSync(`${dir}/package.json`,'utf8'));
 notices+=`\n\n--- ${pkg.name} ${pkg.version} (${pkg.license||'see license'}) ---\n`;
 for(const name of readdirSync(dir).filter(n=>/^licen[cs]e|^copying|^notice/i.test(n))){const f=`${dir}/${name}`;try{notices+=readFileSync(f,'utf8')+'\n';}catch{}}
}
writeFileSync('../assets/THIRD-PARTY-NOTICES.txt',notices);
