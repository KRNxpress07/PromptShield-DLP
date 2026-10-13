import React, {Component} from 'react';
import {createRoot} from 'react-dom/client';
import {BarChart} from '../vendor/bklit/charts/bar-chart';
import {Bar} from '../vendor/bklit/charts/bar';
import {BarXAxis} from '../vendor/bklit/charts/bar-x-axis';
import {YAxis} from '../vendor/bklit/charts/y-axis';
import {Grid} from '../vendor/bklit/charts/grid';
import {ChartTooltip} from '../vendor/bklit/charts/tooltip';

class ChartBoundary extends Component<any,{failed:boolean}> {
  state={failed:false};
  static getDerivedStateFromError(){return {failed:true};}
  render(){return this.state.failed ? <p className="no-data">Chart unavailable. Source values remain below.</p> : this.props.children;}
}
const roots = new Map<Element,ReturnType<typeof createRoot>>();
function mount(node:HTMLElement) {
  if(roots.has(node))return;
  if(node.getBoundingClientRect().width<10)return;
  let spec:any; try{spec=JSON.parse(node.dataset.chart||'');}catch{return;}
  const items=Array.isArray(spec.items)?spec.items.slice(0,100):[];
  const series=Array.isArray(spec.series)?spec.series:[{key:'value',label:'Value',color:'#A78BFA'}];
  const valid=items.flatMap((item:any)=>series.map((s:any)=>item[s.key])).filter((v:any)=>typeof v==='number' && Number.isFinite(v) && v>=0);
  if(!valid.length)return;
  const root=createRoot(node); roots.set(node,root);
  const percent=spec.unit==='%';
  const chartData=items.map((item:any,i:number)=>({name:spec.series?String(item.label):String(i+1).padStart(2,'0'),...Object.fromEntries(series.map((s:any)=>[s.key,typeof item[s.key]==='number'&&Number.isFinite(item[s.key])?item[s.key]:null]))}));
  const max=percent?100:Math.max(...valid)*1.15||1;
  const compact=items.length>12;
  root.render(<ChartBoundary><BarChart data={chartData} xDataKey="name" valueDomain={[0,max]} animationDuration={0} enterTransition={{duration:0}} margin={{left:48,right:16,top:20,bottom:32}} aspectRatio={compact?'3 / 1':'2.6 / 1'}>
    <Grid horizontal numTicksRows={5}/>{series.map((s:any)=><Bar key={s.key} dataKey={s.key} fill={s.color} lineCap="round" animate={false} minBarHeight={0}/>)}
    <YAxis formatValue={v=>`${Number(v.toFixed(1))}${percent?'%':''}`}/><BarXAxis showAllLabels={!compact} maxLabels={compact?8:12}/>
    <ChartTooltip showDatePill={false} content={({point,index}:any)=><div className="research-tooltip"><strong>{items[index]?.label}</strong>{series.map((s:any)=><span key={s.key}>{spec.series?`${s.label}: `:''}{point[s.key]==null?'N/A':`${Number(point[s.key].toFixed(2))}${spec.unit}`}</span>)}</div>}/>
  </BarChart></ChartBoundary>);
}
let queued=false;
function refresh(){queued=false;for(const [node,root] of roots){if(!node.isConnected||node.getBoundingClientRect().width<10){root.unmount();roots.delete(node);}} document.querySelectorAll<HTMLElement>('.bklit-chart[data-chart]').forEach(mount);}
function schedule(){if(!queued){queued=true;requestAnimationFrame(refresh);}}
const observer=new MutationObserver(schedule);
observer.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['hidden']});window.addEventListener('resize',schedule);refresh();
