/**
 * CGM IAM Library v1.0 - 2025-08-30
 */

const CGMIAM_ACCESS_TOKEN_KEY = 'cgm_access_token';
const CGMIAM_REFRESH_TOKEN_KEY = 'cgm_refresh_token';
const CGMIAM_ID_TOKEN_KEY = 'cgm_id_token';

class CgmIamLib {
  constructor(config) {
    this.authEndpoint = `${config.KEYCLOAK_HOST}/realms/nwc/protocol/openid-connect/auth`;
    this.tokenEndpoint = `${config.KEYCLOAK_HOST}/realms/nwc/protocol/openid-connect/token`;
    this.logoutEndpoint = `${config.KEYCLOAK_HOST}/realms/nwc/protocol/openid-connect/logout`;

    this.clientId = config.CLIENT_ID;
    this.redirectUri = config.REDIRECT_URI;
    this.iamHost = config.IAM_HOST;
    this.homeUri = config.HOME_URI;
  }

  async buildAuthUrl() {
    const state = this.generateRandomString();
    const nonce = this.generateRandomString();
    const code_verifier = this.generateCodeVerifier();
    const code_challenge = await this.generateCodeChallenge(code_verifier);
    sessionStorage.setItem('code_verifier', code_verifier);
    sessionStorage.setItem('state', state);
    sessionStorage.setItem('nonce', nonce);

    var lang = "ko"; // ko, en, ja, zh_TW, de, fr, pt, ru, mn, vi, es

    // console.log('lang=' + lang);
    // console.log('code_verifier=' + code_verifier);
    // console.log('code_challenge=' + code_challenge);

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

    // console.log(params.toString());

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
    const code_verifier = sessionStorage.getItem('code_verifier');

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

      sessionStorage.removeItem('state');

      if (!response.ok) {
        //const error = await response.text();
        //console.error('Token exchange failed:', error);
		console.error('Token exchange failed:');
        return;
      }

      const data = await response.json();

      // console.log('Access Token:', data.access_token);
      // console.log('ID Token:', data.id_token);
      // console.log('Refresh Token:', data.refresh_token);

      // id_token validate...
      if( ! this.validateIdToken(data.id_token) ) {
        console.error('Invalid ID Token..');
        return;
      }

      // access_token validate...
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
      sessionStorage.setItem(CGMIAM_ACCESS_TOKEN_KEY, data.access_token);
      sessionStorage.setItem(CGMIAM_REFRESH_TOKEN_KEY, data.refresh_token);
      sessionStorage.setItem(CGMIAM_ID_TOKEN_KEY, data.id_token);
      sessionStorage.removeItem('code_verifier');
      sessionStorage.removeItem('state');
      sessionStorage.removeItem('nonce');

      await this.saveIamSid(payload.sid);

    } catch (err) {
      console.error('Error during token exchange:', err);
    }
  }

  validateIdToken(id_token) {
      const parts = id_token.split('.');
      if (parts.length !== 3) {
        console.error('Invalid ID Token');
        return false;
      }

      // Keycloak 계정 정보
      const parts2 = this.base64UrlDecode(parts[1]);
      if (!parts2)
      {
          console.error('base64UrlDecode failed');
          return false;
      }

      const payload = JSON.parse(parts2);
      // console.log('Decoded Token(Payload):' + JSON.stringify(payload));
      // console.log('Decoded Token(sub):' + payload.sub);
      // console.log('Decoded Token(email):' + payload.email);
      // console.log('Decoded Token(member_name):' + payload.member_name);
      // console.log('Decoded Token(nickname):' + payload.nickname);
      // console.log('Decoded Token(member_verified):' + payload.member_verified);
      // console.log('Decoded Token(nonce):' + payload.nonce);

      const nonce = payload.nonce;
      const old_nonce = sessionStorage.getItem('nonce');

      if( old_nonce === nonce ) return true;
      return false;
  }

  getAuthorizationCodeFromURL() {
    const urlParams = new URLSearchParams(window.location.search);

    const state= urlParams.get('state');
    const old_state = sessionStorage.getItem('state');
    if( old_state !== state ) return null;

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


  //---------------------------------------------------------------

  getSidFromToken(token)
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

    // sid
    return payload.sid;
  }

  async saveIamSid(sid) {

    let url = `${this.iamHost}/api/sid/${sid}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('Token exchange failed:', error);
        return;
      }

    } catch (err) {
      console.error('Error during saveSid:', err);
    }
  }

  async getIamSid(sid) {

    let url = `${this.iamHost}/api/sid/${sid}`;

    try {
      const response = await fetch(url, {
        method: 'GET',
      });

      const body = await response.text();

      if (!response.ok) {
        console.error('Token exchange failed:', body);
        return '';
      }

      return body;

    } catch (err) {
      console.error('Error during getSid:', err);
      return '';
    }
  }

  async removeIamSid(sid) {

    let url = `${this.iamHost}/api/sid/${sid}`;

    try {
      const response = await fetch(url, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('Token exchange failed:', error);
        return;
      }

    } catch (err) {
      console.error('Error during token exchange:', err);
    }
  }

  async checkLogin()
  {
    let sid = this.getSidFromToken(sessionStorage.getItem(CGMIAM_ACCESS_TOKEN_KEY));
    if ( sid == '' ) return false;

    let iam_sid = await this.getIamSid(sid);
    // console.log('iam_sid=' + iam_sid);

    if ( sid !== iam_sid ) {
      sessionStorage.removeItem(CGMIAM_ACCESS_TOKEN_KEY);
      sessionStorage.removeItem(CGMIAM_REFRESH_TOKEN_KEY);
      sessionStorage.removeItem(CGMIAM_ID_TOKEN_KEY);
      return false;
    }

    let token = this.getAccessToken();
    try {
      // access_token validate...
      const parts = token.split('.');
      if (parts.length !== 3) {
        console.error('Invalid Access Token');
        return false;
      }

      // Keycloak 계정 정보
      const parts2 = this.base64UrlDecode(parts[1]);
      if (!parts2) {
        console.error('base64UrlDecode failed');
        return false;
      }

      const payload = JSON.parse(parts2);
      if (!payload.exp) {
        console.error("Invalid Access Token: exp not found");
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      console.log('payload.iat=' + payload.iat);
      console.log('payload.exp=' + payload.exp);
      console.log('exp-iat=====' + (payload.exp - payload.iat));
      console.log('now=========' + now);

      if ( payload.exp > now )
      {
        return true;
      }

      if ( ! await this.refreshToken() ) {
        sessionStorage.removeItem(CGMIAM_ACCESS_TOKEN_KEY);
        sessionStorage.removeItem(CGMIAM_REFRESH_TOKEN_KEY);
        sessionStorage.removeItem(CGMIAM_ID_TOKEN_KEY);
        return false;
      }

      return true;

    } catch (e) {
      console.error("Invalid Access Token:", e);
      return false;
    }

    return true;

  }


  async refreshToken()
  {
    const refresh_token = sessionStorage.getItem(CGMIAM_REFRESH_TOKEN_KEY);

    const params = new URLSearchParams();
    params.append('grant_type', 'refresh_token');
    params.append('refresh_token', refresh_token);
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
        console.error('Token refresh failed:', error);
        return false;
      }

      const data = await response.json();

      // console.log('Access Token:', data.access_token);
      // console.log('ID Token:', data.id_token);
      // console.log('Refresh Token:', data.refresh_token);

      // access_token validate...
      const parts = data.access_token.split('.');
      if (parts.length !== 3) {
        console.error('Invalid Access Token');
        return false;
      }

      // Keycloak 계정 정보
      const parts2 = this.base64UrlDecode(parts[1]);
      if (!parts2)
      {
          console.error('base64UrlDecode failed');
          return false;
      }

      // access_token 저장
      sessionStorage.setItem(CGMIAM_ACCESS_TOKEN_KEY, data.access_token);

      return true;

    } catch (err) {
      console.error('Error during token refresh:', err);
      return false;
    }
  }

  async logout()
  {

    let sid = this.getSidFromToken(sessionStorage.getItem(CGMIAM_ACCESS_TOKEN_KEY));

    if ( sid != '' ) await this.removeIamSid(sid);

    let id_token = sessionStorage.getItem(CGMIAM_ID_TOKEN_KEY);

    sessionStorage.removeItem(CGMIAM_ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(CGMIAM_REFRESH_TOKEN_KEY);
    sessionStorage.removeItem(CGMIAM_ID_TOKEN_KEY);

    const params = new URLSearchParams({
      post_logout_redirect_uri: this.homeUri,
      id_token_hint: id_token,
    });

    window.location.href = `${this.logoutEndpoint}?${params.toString()}`;

  }

  getAccessToken()
  {
    return sessionStorage.getItem(CGMIAM_ACCESS_TOKEN_KEY);
  }


  // fieldName
  // - member_verified - true, false
  // - nickname
  // - member_name
  // - email
  getTokenField(token, fieldName)
  {
    if (!token) return '';

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

}

const cgmIamLib = new CgmIamLib(cgmIamConfig);
