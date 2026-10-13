import React,{useEffect,useRef,useState} from 'react';

/* Measure the chart container, not a percentage-height inner wrapper. Static
 * hidden panels and full-page screenshot resizing can give that wrapper zero
 * height even when its visible chart has a definite CSS height. */
export function MeasuredChartSize({children}:any){
  const ref=useRef<HTMLDivElement>(null);
  const [size,setSize]=useState({width:0,height:0});
  useEffect(()=>{
    const parent=ref.current?.parentElement;if(!parent)return;
    const measure=()=>{const r=parent.getBoundingClientRect();const outer=parent.closest('.bklit-chart');const next={width:r.width,height:r.height||outer?.getBoundingClientRect().height||160};setSize(old=>old.width===next.width&&old.height===next.height?old:next);};
    const observer=new ResizeObserver(measure);observer.observe(parent);measure();
    window.addEventListener('resize',measure);
    return()=>{observer.disconnect();window.removeEventListener('resize',measure);};
  },[]);
  return <div ref={ref} style={{position:'relative',width:'100%'}}>{size.width>0?children(size):null}</div>;
}
