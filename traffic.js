import http from 'k6/http';
import { Counter } from 'k6/metrics';
import { sleep } from 'k6';


let success = new Counter('success_200');
let rateLimited = new Counter('rate_limited_429');

export default function () {
  let res = http.get('http://localhost:8000/download?file_id=69ad336aab4686122655b579');

  if (res.status === 200) {
    success.add(1);
  } else if (res.status === 429) {
    rateLimited.add(1);
  } else {
    console.log(`Unexpected: ${res.status}`);
  }
}