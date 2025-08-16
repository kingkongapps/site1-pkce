const CGMIAM_ACCESS_TOKEN_KEY = 'cgm_access_token';
const CGMIAM_REFRESH_TOKEN_KEY = 'cgm_refresh_token';
const CGMIAM_ID_TOKEN_KEY = 'cgm_id_token';

class CgmIamLib {
  constructor(config) {
    this.authEndpoint = `${config.KEYCLOAK_HOST}/realms/nwc/protocol/openid-connect/auth`;
    this.tokenEndpoint = `${config.KEYCLOAK_HOST}/realms/nwc/protocol/openid-connect/token`;
    this.clientId = config.CLIENT_ID;
    this.redirectUri = config.REDIRECT_URI;
    this.iamHost = config.IAM_HOST;
  }

  async buildAuthUrl() {
    const state = this.generateRandomString();
    const nonce = this.generateRandomString();
    const code_verifier = this.generateCodeVerifier();
    const code_challenge = await this.generateCodeChallenge(code_verifier);
    localStorage.setItem('code_verifier', code_verifier);

    var lang = "ko"; // ko, en, ja, zh_TW, de, fr, pt, ru, mn, vi, es

    //console.log('lang=' + lang);
    //console.log('code_verifier=' + code_verifier);
    //console.log('code_challenge=' + code_challenge);

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: 'openid',
      state: state,
      nonce: nonce,
      kc_locale: lang,
      code_challenge: code_challenge,
      code_challenge_method: 'S256',
    });

    //console.log(params.toString());

    return `${this.authEndpoint}?${params.toString()}`;
  }

  generateRandomString() {
    return Math.random().toString(36).substring(2, 15);
  }

  generateCodeVerifier() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return this.base64UrlEncode(array);
  }

  async generateCodeChallenge(codeVerifier) {
    const data = new TextEncoder().encode(codeVerifier);
    const digest = await window.crypto.subtle.digest("SHA-256", data);
    return this.base64UrlEncode(digest);
  }

  base64UrlEncode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async redirectToLogin() {
    const authUrl = await this.buildAuthUrl();
    window.location.href = authUrl;
  }

  async exchangeCodeForToken(code) {
    const code_verifier = localStorage.getItem('code_verifier');

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('code_verifier', code_verifier);
    params.append('redirect_uri', this.redirectUri);
    params.append('client_id', this.clientId);

    try {
      const response = await fetch(this.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('Token exchange failed:', error);
        return;
      }

      const data = await response.json();

      //console.log('Access Token:', data.access_token);
      //console.log('ID Token:', data.id_token);
      //console.log('Refresh Token:', data.refresh_token);

      // token validate...
      const parts = data.access_token.split('.');
      if (parts.length !== 3) {
        console.error('Invalid Access Token');
        return;
      }

      // Keycloak 계정 정보
      const parts2 = this.base64UrlDecode(parts[1]);
      if (!parts2)
      {
          console.error('base64UrlDecode failed');
          return;
      }

      const payload = JSON.parse(parts2);
      // console.log('Decoded Token(Payload):' + JSON.stringify(payload));
      // console.log('Decoded Token(sub):' + payload.sub);
      // console.log('Decoded Token(email):' + payload.email);
      // console.log('Decoded Token(member_name):' + payload.member_name);
      // console.log('Decoded Token(nickname):' + payload.nickname);
      // console.log('Decoded Token(member_verified):' + payload.member_verified);

      // 회원가입여부 - 미가입시 IAM 회원가입페이지로 이동
      if( ! payload.member_verified ) {
          this.redirectToJoin();
          return;
      }

      // access_token 저장
      localStorage.setItem(CGMIAM_ACCESS_TOKEN_KEY, data.access_token);
      localStorage.setItem(CGMIAM_REFRESH_TOKEN_KEY, data.refresh_token);
      localStorage.setItem(CGMIAM_ID_TOKEN_KEY, data.id_token);

      await this.setIamAccessToken(data.access_token);

    } catch (err) {
      console.error('Error during token exchange:', err);
    }
  }

  getAuthorizationCodeFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('code');
  }

  base64UrlDecode(str) {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      const pad = str.length % 4;
      if (pad) str += '='.repeat(4 - pad);
      try {
        return decodeURIComponent(escape(atob(str)));
      } catch (err) {
    return "";
      }
  }

  async buildJoinUrl() {

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri
    });

    return `${this.iamHost}/join?${params.toString()}`;
  }

  async redirectToJoin() {
    const joinUrl = await this.buildJoinUrl();
    window.location.href = joinUrl;
  }

  // function setCookie(name, value) {
  //   const expires = new Date();
  //   expires.setTime(expires.getTime() + hours * 60 * 60 * 1000);
  //   document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires.toUTCString()}; path=/`;
  // }

  // // 쿠키 읽기
  // function getCookie(name) {
  //   const cookies = document.cookie.split(';');
  //   for (let c of cookies) {
  //     const [key, val] = c.trim().split('=');
  //     if (key === name) return decodeURIComponent(val);
  //   }
  //   return null;
  // }

  // // 쿠키 삭제
  // function deleteCookie(name) {
  //   document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/`;
  // }

  // 샘플화면 - 로그인 버튼
  //document.getElementById('loginButton').addEventListener('click', redirectToLogin);


  getUuidFormToken(token)
  {
    if( token == null ) return '';
    const parts = token.split('.');
    if (parts.length !== 3) {
      return '';
    }

    const parts2 = this.base64UrlDecode(parts[1]);
    if (!parts2)
    {
      console.error('this.base64UrlDecode failed');
      return '';
    }

    const payload = JSON.parse(parts2);

    // uuid
    return payload.sub;
  }


  // iframe 생성될 때까지 기다리는 유틸
  getStorageFrame() {
    if (this.storageFrame && this.storageFrame.contentWindow) return Promise.resolve(this.storageFrame);

    this.storageFrame = document.createElement("iframe");
    this.storageFrame.src = `${this.iamHost}/token.html`;
    //this.storageFrame.style.display = "none";

    const p = new Promise((resolve, reject) => {
      this.storageFrame.addEventListener("load", () => resolve(this.storageFrame), { once: true });
      this.storageFrame.addEventListener("error", () => reject(new Error("Storage iframe load failed")), { once: true });
    });

    document.body.appendChild(this.storageFrame);
    return p;
  }

  // 한 번만 응답을 기다리는 유틸 (타임아웃 지원)
  waitForMessageOnce({ type, fromWindow, origin, timeout = 5000 }) {
    return new Promise((resolve, reject) => {
      const onMessage = (event) => {
        if (event.source !== fromWindow) return;              // 해당 iframe에서 온 메시지인지
        if (event.origin !== origin) return;                  // origin 검사
        if (!event.data || event.data.type !== type) return;  // 타입 일치
        window.removeEventListener("message", onMessage);
        clearTimeout(timer);
        resolve(event.data);
      };

      const timer = setTimeout(() => {
        window.removeEventListener("message", onMessage);
        reject(new Error(`Timed out waiting for "${type}" message`));
      }, timeout);

      window.addEventListener("message", onMessage, { once: false });
    });
  }

  // 공용 postMessage 래퍼
  async postToStorage(msg, { expectType, timeout } = {}) {
    const frame = await this.getStorageFrame();
    const win = frame.contentWindow;

    const waitPromise = expectType
      ? this.waitForMessageOnce({ type: expectType, fromWindow: win, origin: this.iamHost, timeout })
      : Promise.resolve(null);

    win.postMessage(msg, this.iamHost);
    return waitPromise;
  }

  // IAM 토큰 가져오기
  async getIamAccessToken(timeout = 5000) {
    const data = await this.postToStorage(
      { type: "getIamAccessToken" },
      { expectType: "getIamAccessTokenResult", timeout }
    );

    return data?.value ?? null;
  }

  // IAM 토큰 저장하기
  async setIamAccessToken(token, timeout = 1000) {

    const data = await this.postToStorage(
      { type: "setIamAccessToken", value: token },
      { expectType: "setIamAccessTokenResult", timeout }
    );

    return data?.value ?? null;
  }

  // 로그인 여부. 로컬 토큰과 IAM 사이트 토크에 있는 uuid(sub) 값 비교하여 같은 경우만 true.
  async checkLogin()
  {
    let iam_token = await this.getIamAccessToken();
    console.log('iam_token=' + iam_token);

    let local_uuid = this.getUuidFormToken(localStorage.getItem(CGMIAM_ACCESS_TOKEN_KEY));
    //console.log('local_uuid=' + local_uuid);
    if ( local_uuid == '' ) return false;

    let iam_uuid = this.getUuidFormToken(iam_token);
    if( iam_token ) {
        iam_uuid = this.getUuidFormToken(iam_token);
        //console.log('iam_uuid=' + iam_uuid);
        if ( iam_uuid == '' ) return false;
    }

    if ( local_uuid !== iam_uuid ) return false;

    return true;

  }

  getAccessToken()
  {
    return localStorage.getItem(CGMIAM_ACCESS_TOKEN_KEY);
  }

  getTokenField(token, fieldName)
  {
    if (typeof token !== 'string' || !token.includes('.')) {
      console.error('Invalid Access Token: not a JWT string');
      return '';
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      console.error('Invalid Access Token: JWT must have 3 parts');
      return;
    }

    // Keycloak 계정 정보
    const parts2 = this.base64UrlDecode(parts[1]);
    if (!parts2)
    {
        console.error('base64UrlDecode failed');
        return;
    }

    const payload = JSON.parse(parts2);

    // fieldName이 없으면 payload 전체 반환
    if (!fieldName) return payload;

    // "a.b.c" 같은 중첩 경로 지원
    const value = fieldName.split('.').reduce((obj, key) => (obj ? obj[key] : undefined), payload);

    // undefined/null이면 기본값
    return value ?? '';

    // console.log('Decoded Token(Payload):' + JSON.stringify(payload));
    // console.log('Decoded Token(sub):' + payload.sub);
    // console.log('Decoded Token(email):' + payload.email);
    // console.log('Decoded Token(member_name):' + payload.member_name);
    // console.log('Decoded Token(nickname):' + payload.nickname);
    // console.log('Decoded Token(member_verified):' + payload.member_verified);
  }


  logout()
  {
    localStorage.removeItem(CGMIAM_ACCESS_TOKEN_KEY);
    localStorage.removeItem(CGMIAM_REFRESH_TOKEN_KEY);

    // 로그아웃의 경우 루트(/)를 redirect_uri로 설정
    const baseUrl = new URL(this.redirectUri).origin;

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: baseUrl
    });

    window.location.href = `${this.iamHost}/logout?${params.toString()}`;

  }

}

const cgmIamLib = new CgmIamLib(cgmIamConfig);
