"""Read the existing MT5 demo session; this module has no execution operation."""
import argparse, datetime as dt, hashlib, json, os, pathlib, sys
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--symbol',default='GBPUSD');args=parser.parse_args()
    output=pathlib.Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
    try:
        import MetaTrader5 as mt5
    except ImportError:
        print(json.dumps({'status':'unavailable','reason':'MetaTrader5 Python package missing'}));return 2
    if not mt5.initialize():
        print(json.dumps({'status':'unavailable','reason':'MT5 terminal connection failed'}));return 2
    try:
        account=mt5.account_info()
        if account is None or account.trade_mode!=mt5.ACCOUNT_TRADE_MODE_DEMO:
            print(json.dumps({'status':'blocked','reason':'Connector requires an existing demo session'}));return 2
        now=dt.datetime.now(dt.timezone.utc)
        deals=mt5.history_deals_get(now-dt.timedelta(days=7),now)
        positions=mt5.positions_get()
        rates=mt5.copy_rates_from_pos(args.symbol,mt5.TIMEFRAME_M1,1,500)
        if deals is None or positions is None or rates is None:
            print(json.dumps({'status':'unavailable','reason':'Broker history or market data unavailable'}));return 2
        # Public receipt never includes login, account balance, server, position tickets or strategy comments.
        bars=[{'time':int(r['time']),'open':float(r['open']),'high':float(r['high']),'low':float(r['low']),'close':float(r['close']),'volume':int(r['tick_volume'])} for r in rates]
        private={'mode':'read-only-demo','observedAt':now.isoformat(),'symbol':args.symbol,'bars':bars,'dealCount':len(deals),'positionCount':len(positions)}
        output.write_text(json.dumps(private),encoding='utf-8')
        print(json.dumps({'status':'connected','mode':'actual-read-only-demo','bars':len(bars),'historyRead':True,'positionsRead':True,'snapshotSha256':hashlib.sha256(output.read_bytes()).hexdigest(),'ordersSubmitted':0}))
        return 0
    finally:mt5.shutdown()
if __name__=='__main__':sys.exit(main())
