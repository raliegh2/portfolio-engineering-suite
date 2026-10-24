import {PaperExchange}from'./replay.js';
import {digest}from'./common.js';
// This exercises execution mechanics on observed prices; it is not a strategy or an account-currency backtest.
export function replayMarketHistory(snapshot){
 if(!Array.isArray(snapshot?.bars)||snapshot.bars.length<2)throw new Error('At least two bars required');
 const bars=[...snapshot.bars].sort((a,b)=>a.time-b.time),seen=new Set();
 for(const bar of bars){
  if(!Number.isSafeInteger(bar.time)||seen.has(bar.time)||!['open','high','low','close'].every(k=>Number.isFinite(bar[k])&&bar[k]>0)||bar.high<Math.max(bar.open,bar.close)||bar.low>Math.min(bar.open,bar.close))throw new Error('Invalid market bars');seen.add(bar.time);
 }
 const scale=100000,first=Math.round(bars[0].close*scale),last=Math.round(bars.at(-1).close*scale);
 const time=n=>new Date(Date.UTC(2000,0,1)+n*1000).toISOString();
 const events=[{id:'submit-buy',ts:time(0),type:'submit',orderId:'buy',side:'buy',quantity:1,limitCents:first+1},
 {id:'fill-buy',ts:time(1),type:'fill',orderId:'buy',quantity:1,priceCents:first},
 {id:'submit-sell',ts:time(2),type:'submit',orderId:'sell',side:'sell',quantity:1,limitCents:last-1},
 {id:'fill-sell',ts:time(3),type:'fill',orderId:'sell',quantity:1,priceCents:last}];
 const config={cashCents:Math.max(first,last)*10,maxPosition:1,feePerUnit:0,slippageCents:1};
 const one=new PaperExchange(config),two=new PaperExchange(config);for(const e of events){one.apply(e);two.apply(e);}
 return {mode:'actual-broker-data-offline-replay',sourceBars:bars.length,sourceSha256:digest(snapshot),priceScale:scale,deterministic:one.hash()===two.hash(),ledgerSha256:one.hash(),finalPosition:one.state.position,ordersSubmittedToBroker:0,
 assumptions:'One simulated unit; zero fees and one quote-unit slippage; logical simulation clocks preserve price order without asserting broker timestamp timezone. Not strategy performance or account-currency profit.'};
}
