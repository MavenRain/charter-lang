// Runs entries of a langc Wasm module and prints each result as `langc eval`
// does: a number, or `trap` when the module traps.
// Usage: node test/run-wasm.mjs FILE NAME [ARGS...]
//        node test/run-wasm.mjs FILE -   (one `NAME [ARGS...]` line on stdin per call)
//        node test/run-wasm.mjs --words FILE NAME [WORDS...] | --words FILE -
//          (a stream entry of `langc build --words`, Q-S3-7: the output words)
//        Before these: `--load OFFSET FILE` pairs set the bytes of FILE at the byte
//        OFFSET of the memory before the first call (S5 U2b: the TFHE keys).
//        First of all, `--time`: stderr gets `host ARCH node VERSION`, then
//        `time MS` for each call (the entry call only; S5 O4).
import { readFileSync } from "node:fs";

const takeLoads = (a, loads) =>
  a[0] === "--load" ? takeLoads(a.slice(3), [...loads, [Number(a[1]), a[2]]]) : [a, loads];
const timed = process.argv[2] === "--time";
const [argv, loads] = takeLoads(process.argv.slice(timed ? 3 : 2), []);
const stream = argv[0] === "--words";
const [file, name, ...args] = stream ? argv.slice(1) : argv;
if (file === undefined || name === undefined) {
  process.stderr.write("usage: node test/run-wasm.mjs [--time] [--load OFFSET FILE]... [--words] FILE NAME [ARGS...] | [--words] FILE -\n");
  process.exit(2);
}
const instance = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(file)), {});
loads.forEach(([offset, path]) => {
  const memory = instance.exports.memory;
  const bytes = readFileSync(path);
  const end = offset + bytes.length;
  if (end > memory.buffer.byteLength) memory.grow(Math.ceil((end - memory.buffer.byteLength) / 65536));
  new Uint8Array(memory.buffer, offset, bytes.length).set(bytes);
});
if (timed) process.stderr.write(`host ${process.arch} node ${process.version}\n`);

// With --time: the time of the entry call F only.
const timeIt = (f) => {
  const t = performance.now();
  const r = f();
  if (timed) process.stderr.write(`time ${(performance.now() - t).toFixed(3)}\n`);
  return r;
};

// The input words go to byte 0; the result is the address A of [m, the m words].
const run = (fn, words) => {
  if (!stream) return BigInt.asUintN(64, timeIt(() => fn(...words.map(BigInt)))).toString();
  const memory = instance.exports.memory;
  const bytes = 8 * words.length;
  if (bytes > memory.buffer.byteLength) memory.grow(Math.ceil((bytes - memory.buffer.byteLength) / 65536));
  new BigUint64Array(memory.buffer, 0, words.length).set(words.map((w) => BigInt.asUintN(64, BigInt(w))));
  const a = Number(BigInt.asUintN(64, timeIt(() => fn(BigInt(words.length))))) / 8;
  const view = new BigUint64Array(memory.buffer);
  return Array.from({ length: Number(view[a]) }, (_, i) => view[a + 1 + i].toString()).join(" ");
};

const call = ([entry, ...words]) => {
  const fn = instance.exports[entry];
  if (typeof fn !== "function") throw new Error(`no exported entry '${entry}'`);
  try {
    return run(fn, words);
  } catch (e) {
    if (e instanceof WebAssembly.RuntimeError) return "trap";
    throw e;
  }
};

const calls = name === "-"
  ? readFileSync(0, "utf8").split("\n").filter((line) => line !== "").map((line) => line.split(" "))
  : [[name, ...args]];
process.stdout.write(calls.map((c) => call(c) + "\n").join(""));
