import fs from 'node:fs/promises';
import {replayMarketHistory}from'../src/market-history.js';
import {writeJson}from'../src/common.js';
const [input,output='evidence/broker-history-verification.json']=process.argv.slice(2);
const report=replayMarketHistory(JSON.parse(await fs.readFile(input,'utf8')));await writeJson(output,report);console.log(JSON.stringify(report));
