import {readFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';

export function violations(text,path='workflow') {
  const result=[];
  if(/^\s*(?:-\s*)?uses:\s*["']?actions\/(?:upload|download)-artifact@/mi.test(text)) result.push(`${path}: GitHub artifact storage is prohibited`);
  if(/\bgh\s+release\s+(?:upload|download)\b/.test(text)) result.push(`${path}: binary GitHub release transport is prohibited`);
  const lines=text.split('\n');
  for(let i=0;i<lines.length;i++) {
    if(!/uses:\s*["']?(?:softprops\/action-gh-release|actions\/upload-release-asset)@/.test(lines[i])) continue;
    if(lines[i].includes('upload-release-asset')) {result.push(`${path}:${i+1}: GitHub binary release uploads are prohibited`);continue;}
    const indent=lines[i].match(/^\s*/)[0].length;
    for(let j=i+1;j<lines.length;j++) {
      if(/^\s*-\s/.test(lines[j])&&lines[j].match(/^\s*/)[0].length<=indent)break;
      if(/^\s*files\s*:/.test(lines[j]))result.push(`${path}:${j+1}: release files belong in R2`);
    }
  }
  if(/\bbash\s+preview\/publish\.sh\b/.test(text))result.push(`${path}: generated review binaries belong in R2`);
  return result;
}

export async function check(directory='.github/workflows') {
  const errors=[];
  for(const name of await readdir(directory))if(/\.ya?ml$/.test(name))errors.push(...violations(await readFile(join(directory,name),'utf8'),name));
  if(errors.length)throw Error(errors.join('\n'));
  console.log('Artifact storage policy passes: build outputs use Cloudflare R2.');
}
if(process.argv[1]&&resolve(process.argv[1])===new URL(import.meta.url).pathname)check(process.argv[2]).catch(error=>{console.error(error.message);process.exitCode=1;});
