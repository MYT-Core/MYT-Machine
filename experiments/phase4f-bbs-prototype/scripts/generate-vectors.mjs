import {mkdir, writeFile} from 'node:fs/promises';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildVector} from '../src/fixture.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vectorDirectory = resolve(root, 'vectors');
const vectorPath = resolve(vectorDirectory, 'phase4f-v1.json');
await mkdir(vectorDirectory, {recursive: true});
const vector = await buildVector();
await writeFile(vectorPath, `${JSON.stringify(vector, null, 2)}\n`, 'utf8');
console.log(`generated ${vectorPath}`);
console.log(`raw BBS proof: ${vector.sizes.raw_bbs_proof_bytes} bytes`);
console.log(`complete presentation JSON: ${vector.sizes.complete_presentation_json_bytes} bytes`);
