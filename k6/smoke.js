import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 5,
  duration: "20s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

const baseUrl = __ENV.API_BASE_URL || "http://localhost:4000";

export default function () {
  const health = http.get(`${baseUrl}/health`);
  check(health, {
    "health ok": (res) => res.status === 200,
  });

  const ready = http.get(`${baseUrl}/ready`);
  check(ready, {
    "ready responded": (res) => res.status === 200 || res.status === 503,
  });

  sleep(1);
}
