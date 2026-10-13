import {chromium} from 'playwright';
import {mkdirSync,writeFileSync} from 'node:fs';
const folder='../../docs/presentation-screenshots';mkdirSync(folder,{recursive:true});
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const results=[];
for(const [width,height] of [[1920,1080],[1600,900],[1366,768],[390,844]]){
 const page=await browser.newPage({viewport:{width,height},reducedMotion:'reduce'});
 const errors=[],network=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith('http://127.0.0.1:8788'))network.push(r.url());});
 await page.goto('http://127.0.0.1:8788/#local-model');
 await page.waitForFunction(()=>document.getElementById('local-model-metrics').textContent.includes('73.33%'));
 if(width>800)await page.locator('#presentation-toggle').click();
 for(const group of ['performance','comparison','validation']){
   await page.locator(`[data-local-page="${group}"]`).click();await page.waitForTimeout(2000);
   const checks=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth, bottom:document.querySelector('#view-local-model').getBoundingClientRect().bottom,charts:[...document.querySelectorAll('#view-local-model .bklit-chart')].filter(n=>n.getBoundingClientRect().width>0).map(n=>({width:n.clientWidth,svg:!!n.querySelector('svg'),error:n.textContent.includes('Chart unavailable')})),configHidden:getComputedStyle(document.querySelector('.connection-panel')).display==='none'}));
   await page.screenshot({path:`${folder}/local-${group}-${width}x${height}.png`,fullPage:width<800});
   results.push({width,height,group,...checks,errors:[...errors],externalRequests:[...network]});
 }
 if(width>800){
  for(const view of ['overview','benchmarks','detection','sanitization','performance','scanner']){
   await page.goto(`http://127.0.0.1:8788/#${view}`);await page.waitForTimeout(500);if(await page.locator('#presentation-toggle').getAttribute('aria-pressed')!=='true')await page.locator('#presentation-toggle').click();await page.waitForTimeout(2000);
   await page.screenshot({path:`${folder}/${view}-${width}x${height}.png`,fullPage:true});
   results.push({width,height,view,errors:[...errors],...(await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,bottom:document.querySelector('.view:not([hidden])').getBoundingClientRect().bottom,charts:[...document.querySelectorAll('.view:not([hidden]) .bklit-chart')].filter(n=>n.getBoundingClientRect().width>0).map(n=>({svg:!!n.querySelector('svg'),bars:n.querySelectorAll('svg path,svg rect[fill="#A78BFA"]').length,error:n.textContent.includes('Chart unavailable')}))})))});
   if(view==='performance'||view==='sanitization'){
    const group=view==='performance'?'throughput':'examples';await page.locator(`[data-research-group="${view}"][data-research-page="${group}"]`).click();await page.waitForTimeout(2000);await page.screenshot({path:`${folder}/${view}-${group}-${width}x${height}.png`,fullPage:true});
    results.push({width,height,view:`${view}-${group}`,errors:[...errors],...(await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,bottom:document.querySelector('.view:not([hidden])').getBoundingClientRect().bottom,charts:[...document.querySelectorAll('.view:not([hidden]) .bklit-chart')].filter(n=>n.getBoundingClientRect().width>0).map(n=>({svg:!!n.querySelector('svg'),bars:n.querySelectorAll('svg path,svg rect[fill="#A78BFA"]').length,error:n.textContent.includes('Chart unavailable')}))})))});
   }
  }
 }
 await page.close();
}
await browser.close();writeFileSync('../../docs/FINAL_FRONTEND_VISUAL_QA.json',JSON.stringify(results,null,2));
console.log(JSON.stringify(results.map(r=>({width:r.width,group:r.group||r.view,overflow:r.overflow,bottom:r.height,errors:r.errors,charts:r.charts})),null,2));
