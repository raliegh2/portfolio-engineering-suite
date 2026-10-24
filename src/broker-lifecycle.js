import { digest, requireText, utc } from './common.js';
// Venue observations are recorded even when they breach policy; risk state must reflect actual fills.
export class BrokerLifecycle {
  constructor({maxPosition=10}={}){if(!Number.isInteger(maxPosition)||maxPosition<1)throw new Error('Invalid limit');this.state={maxPosition,position:0,connected:true,killed:false,orders:{},seen:{},events:[],breaches:[]};}
  apply(event){
    requireText(event.id,'event');utc(event.ts);
    if(['__proto__','constructor','prototype'].includes(event.id))throw new Error('Invalid event');
    const prior=this.state.seen[event.id];if(prior){if(prior!==digest(event))throw new Error('Event conflict');return {duplicate:true};}
    const next=structuredClone(this.state),positive=n=>Number.isSafeInteger(n)&&n>0;
    const key=event.orderId;if(key&&['__proto__','constructor','prototype'].includes(key))throw new Error('Invalid order');
    const order=key&&Object.hasOwn(next.orders,key)?next.orders[key]:null;
    if(event.type==='submit.requested'){
      requireText(key,'order ID');if(order)throw new Error('Duplicate order');
      if(!next.connected||next.killed)throw new Error('Submission disabled');
      if(!positive(event.quantity))throw new Error('Invalid quantity');
      const reserved=Object.values(next.orders).filter(o=>!o.cancelAcknowledged).reduce((n,o)=>n+o.quantity-o.filled,0);
      if(next.position+reserved+event.quantity>next.maxPosition)throw new Error('Exposure cap');
      next.orders[key]={quantity:event.quantity,filled:0,accepted:false,cancelPending:false,cancelAcknowledged:false};
    }else if(event.type==='connection'){if(typeof event.connected!=='boolean')throw new Error('Invalid connection');next.connected=event.connected;}
    else if(event.type==='kill'){next.killed=true;for(const o of Object.values(next.orders))if(o.filled<o.quantity&&!o.cancelAcknowledged)o.cancelPending=true;}
    else{
      if(!order)throw new Error('Unknown order');
      if(event.type==='accepted')order.accepted=true;
      else if(event.type==='cancel.requested')order.cancelPending=true;
      else if(event.type==='cancel.ack'){order.cancelAcknowledged=true;order.cancelPending=false;}
      else if(event.type==='fill'){
        if(!positive(event.quantity)||order.filled+event.quantity>order.quantity)throw new Error('Invalid fill');
        order.filled+=event.quantity;next.position+=event.quantity;
        if(next.position>next.maxPosition){next.killed=true;next.breaches.push({eventId:event.id,reason:'Actual fills exceed cap'});}
      }else throw new Error('Unknown lifecycle event');
    }
    next.seen[event.id]=digest(event);next.events.push(structuredClone(event));this.state=next;return {duplicate:false};
  }
  reconcile(snapshot){
    if(!Number.isSafeInteger(snapshot.position)||snapshot.position<0)throw new Error('Invalid broker snapshot');
    const discrepancy=snapshot.position!==this.state.position;
    if(discrepancy){this.state.breaches.push({reason:'Broker position discrepancy',expected:this.state.position,actual:snapshot.position});this.state.position=snapshot.position;this.state.killed=true;}
    return {matches:!discrepancy,blocked:this.state.killed};
  }
}
