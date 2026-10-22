// This script includes/is based on the following packages respectively:
//	https://github.com/espruino/EspruinoDocs/blob/master/modules/crypto.js
//	https://github.com/espruino/EspruinoDocs/blob/master/modules/ws.js



const net = require('net');
const http = require('http');

/* Copyright (c) 2016 Rhys Williams, @jumjum. See the file LICENSE for copying permission. */
/* Most boards have 'crypto' built in, but some don't. If they don't then
this module contains SHA1, which is needed for websocket support. */
const SHA1 = (msg) => {
	function f(s, x, y, z)	{
		if(s===0)		return (x & y) ^ (~x & z);
		else if(s===1)	return  x ^ y  ^ z;
		else if(s===2)	return (x & y) ^ (x & z) ^ (y & z);
		else			return  x ^ y  ^ z;
	}
	function split(n){
		for(i=3; i>=0;i--){
			M.push((n>>(i*8)) & 0xff);
		}
	}
	var K,N,M,i,j,H0,H1,H2,H3,H4;
	var W,a,b,c,d,e,s,T;
	var flt = 0xffffffff;
	msg = E.toString(msg)+'\x80';
	K = new Int32Array([ 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 ]);
	N = Math.ceil((msg.length/4 + 2)/16);
	M = new Array(N);
	msg = E.toUint8Array(msg);
	for(i=0; i<N; i++){
		a = i <<6;
		c = new Int32Array(16);
		for(j=0;j<16;j++){
			b = a +(j<<2);
			c[j] = (msg[b]<<24) | (msg[b+1]<<16) | (msg[b+2]<<8) | (msg[b+3]);
		}
		M[i] = c;
	}
	M[N-1][14] = ((msg.length-1)*8) / Math.pow(2, 32); M[N-1][14] = Math.floor(M[N-1][14]);
	M[N-1][15] = ((msg.length-1)*8) & flt;
	H0 = 0x67452301;H1 = 0xefcdab89;H2 = 0x98badcfe;H3 = 0x10325476;H4 = 0xc3d2e1f0;
	W = new Int32Array(80);
	for(i=0; i<N; i++){
		for(j=0;  j<16; j++) W[j] = M[i][j];
		for(j=16; j<80; j++){
			a = W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16];
			W[j] = (a<<1)|(a>>>31);
		}
		a = H0; b = H1; c = H2; d = H3; e = H4;
		for(j=0; j<80; j++){
			s = Math.floor(j/20);
			T = (((a<<5) | (a>>>27)) + f(s,b,c,d) + e + K[s] + W[j]) & flt;
			e = d; d = c; c = (b<<30) | (b>>>2);b = a;a = T;
		}
		H0 = (H0 + a) & flt;H1 = (H1 + b) & flt; H2 = (H2 + c) & flt;
		H3 = (H3 + d) & flt;H4 = (H4 + e) & flt;
	}
	M = [];
	split(H0);split(H1);split(H2);split(H3);split(H4);
	return E.toUint8Array(M).buffer;
};












/* Copyright (c) 2015 Sameh Hady, Gordon Williams. See the file LICENSE for copying permission. */


/*
 Simple WebSocket protocol wrapper for Espruino sockets.

 * KEYWORDS: Module,websocket,ws,socket

 Websocket implementation on Espruino, it let you control your Espruino from the cloud without the need to know it's IP.
 You will need to use it with a websocket server.

 How to use the ws module:

 ```javascript
 // Connect to WiFi, then...

 // =============================== CLIENT
 var WebSocket = require("ws");
 var ws = new WebSocket("HOST",{
			path: '/echo',
			port: 8080,
			protocolVersion: 13,
			protocol : "echo-protocol", // optional websocket protocol
			origin: 'Espruino',
			keepAlive: 60,	// Ping Interval in seconds.
			headers:{ some:'header', 'another-header':42 } // optional websocket headers
		});

 ws.on('open', function(){
	 console.log("Connected to server");
 });

 ws.on('message', function(msg){
	 console.log("MSG: " + msg);
 });

 ws.on('close', function(){
	 console.log("Connection closed");
 });

 //Send message to server
 ws.send("Hello Server");

 // =============================== SERVER
 var page = '<html><body><script>var ws;setTimeout(function(){';
 page += 'ws = new WebSocket("ws://" + location.host + "/my_websocket", "protocolOne");';
 page += 'ws.onmessage = function(event){ console.log("MSG:"+event.data); };';
 page += 'setTimeout(function(){ ws.send("Hello to Espruino!"); }, 1000);';
 page += '},1000);</script></body></html>';

 function onPageRequest(req, res){
	res.writeHead(200, {'Content-Type': 'text/html'});
	res.end(page);
 }

 var server = require('ws').createServer(onPageRequest);
 server.listen(8000);
 server.on("websocket", function(ws){
		ws.on('message',function(msg){ print("[WS] "+JSON.stringify(msg)); });
		ws.send("Hello from Espruino!");
 });
```
*/


/** Minify String.fromCharCode() call */
const strChr = String.fromCharCode;

const buildKey = () => {
	let randomString = btoa(Math.random().toString(36).substr(2,8) + Math.random().toString(36).substr(2,8));
	let toHash = randomString + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
	return{
		source: randomString,
		hashed: btoa(SHA1(toHash))
	};
};

class WebSocket extends EventEmitter{
	constructor(host, options={}){
		super();
		this._socket = null;
		this._host = host;
		this._port = options.port || 80;
		this._protocolVersion = options.protocolVersion || 13;
		this._origin = options.origin || 'Espruino';
		this._keepAlive = options.keepAlive * 1000 || 60000;
		this._masking = options.masking!==undefined ? options.masking : true;
		this._path = options.path || '/';
		this._protocol = options.protocol;
		this._lastData = '';
		this._key = buildKey();
		this._connected = options.connected || false;
		this._headers = options.headers || {};
	};

	initializeConnection(){
		this._socket = net.createConnection({
			host: this._host,
			port: this._port,
		}, ()=>{
			// this._tcpConnected = true; // tcp is connected

			// this._socket.write(this.buildConnectPacket());

			// this._heartbeatT = setInterval(this.heartbeat.bind(this), (this._keepAliveS - 5) * 1000);
		});

		this._socket.on('data', this.parseData.bind(this));
		this._socket.on('close', function(){
			if(this.pingTimer){
				clearInterval(this.pingTimer);
				this.pingTimer = undefined;
			}
			this.emit('close');
		});

		this.handshake();
	};

	parseData(data){
		// see https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
		// Note, docs specify bits 0-7, etc - but BIT 0 is the MSB, 7 is the LSB
		this.emit('rawData', data);

		if(this._lastData.length){
			data = this._lastData+data;
			this._lastData='';
		}

		if(!this._connected){
			// FIXME - not a good idea!
			if(data.indexOf(this._key.hashed) > -1 && data.indexOf('\r\n\r\n') > -1){
				this.emit('handshake');
				this.pingTimer = setInterval(function(){
					this.send('ping', 0x89);
				}, this._keepAlive);
				data = data.substring(data.indexOf('\r\n\r\n') + 4);
				this._connected = true;
				this.emit('open');
			}
			this._lastData = data;
			return;
		}

		while(data.length){
			let offset = 2;
			let opcode = data.charCodeAt(0)&15;
			let dataLen = data.charCodeAt(1)&127;
			if(dataLen==126){
				dataLen = data.charCodeAt(3) | (data.charCodeAt(2)<<8);
				offset += 2;
			}else if(dataLen==127) throw new Error('Messages >65535 in length unsupported');
			let pktLen = dataLen+offset+((data.charCodeAt(1)&128)?4/*mask*/:0);
			if(pktLen > data.length){
				// we received the start of a packet, but not enough of it for a full message.
				// store it for later, so when we get the next packet we can do the whole message
				this._lastData = data;
				return;
			}

			switch(opcode){
				case 0xA:
					this.emit('pong');
					break;
				case 0x9:
					this.send('pong', 0x8A);
					this.emit('ping');
					break;
				case 0x8:
					this._socket.end();
					break;
				case 0:
				case 1:
					let mask = [ 0,0,0,0 ];
					if(data.charCodeAt(1)&128 /* mask */){
						mask = [
							data.charCodeAt(offset++),
							data.charCodeAt(offset++),
							data.charCodeAt(offset++),
							data.charCodeAt(offset++)
						];
					}
					let msg = '';
					for(let i=0; i<dataLen; i++)	msg += String.fromCharCode(data.charCodeAt(offset++) ^ mask[i&3]);
					this.emit('message', msg);
					break;
				default:
//					console.log('WS: Unknown opcode '+opcode);
					console.log(`WS: Unknown opcode ${opcode}`);
				}
				data = data.substr(pktLen);
			}
	};

	handshake(){
//		let socketHeader = [
//			'GET ' + this._path + ' HTTP/1.1',
//			'Host: ' + this._host,
//			'Upgrade: websocket',
//			'Connection: Upgrade',
//			'Sec-WebSocket-Key: ' + this._key.source,
//			'Sec-WebSocket-Version: ' + this._protocolVersion,
//			'Origin: ' + this._origin
//		];
		let socketHeader = [
			`GET ${this._path} HTTP/1.1`,
			`Host: ${this._host}`,
			'Upgrade: websocket',
			'Connection: Upgrade',
			`Sec-WebSocket-Key: ${this._key.source}`,
			`Sec-WebSocket-Version: ${this._protocolVersion}`,
			`Origin: ${this._origin}`
		];
//		if(this._protocol)	socketHeader.push('Sec-WebSocket-Protocol: '+this._protocol);
		if(this._protocol)	socketHeader.push(`Sec-WebSocket-Protocol: ${this._protocol}`);

		for(let key in this._headers){
//			if(this._headers.hasOwnProperty(key))	socketHeader.push(key+': '+this._headers[key]);
			if(this._headers.hasOwnProperty(key))	socketHeader.push(`${key}: ${this._headers[key]}`);
		}

		this._socket.write(socketHeader.join('\r\n')+'\r\n\r\n');
	};

	/** Send message based on opcode type */
	send(msg, opcode=0x81){
		let size = msg.length;
		if(msg.length>125)	size = 126;
		this._socket.write(strChr(opcode, size + ( this._masking ? 128 : 0 )));

		if(size===126){
			// Need to write extra bytes for longer messages
			this._socket.write(strChr(msg.length >> 8));
			this._socket.write(strChr(msg.length));
		}

		if(this._masking){
			let mask = [];
			let masked = '';
			for(let ix=0; ix<4; ix++){
				let rnd = Math.floor( Math.random() * 255 );
				mask[ix] = rnd;
				masked += strChr(rnd);
			}
			for(let ix=0; ix<msg.length; ix++)	masked += strChr(msg.charCodeAt(ix) ^ mask[ix & 3]);
			this._socket.write(masked);
		}else{
			this._socket.write(msg);
		}
	};

	close(){
		this._socket.end();
	};
};

/** Create a WebSocket client */
exports = function(host, options){
	const ws = new WebSocket(host, options);
	ws.initializeConnection();
	return ws;
};

/** Create a WebSocket server */
exports.createServer = function(cb){
	const server = http.createServer(function(req, res){
		if(req.headers.Connection && req.headers.Connection.indexOf('Upgrade')>=0){
			let key = req.headers['Sec-WebSocket-Key'];
			let accept = btoa(E.toString(SHA1(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
			let headers = {
				'Upgrade': 'websocket',
				'Connection': 'Upgrade',
				'Sec-WebSocket-Accept': accept
			};
			if(req.headers['Sec-WebSocket-Protocol'])	headers['Sec-WebSocket-Protocol'] = req.headers['Sec-WebSocket-Protocol'];
			res.writeHead(101, headers);

			const ws = new WebSocket(undefined, { masking:false, connected:true });
			ws.socket = res;
			req.on('data', ws.parseData.bind(ws) );
			req.on('close', function(){
				// if srvPing is undefined, we already emitted a 'close'
				clearInterval(ws.srvPing);
				ws.srvPing = undefined;
				// emit websocket close event
				ws.emit('close');
			});
			/** Start a server ping at the keepAlive interval	**/
			ws.srvPing = setInterval(function(){
				ws.emit('ping', true); // true: indicates a server ping
				ws.send('ping', 0x89);
			}, ws.keepAlive);
			server.emit('websocket', ws);
		}else cb(req, res);
	});
	return server;
};
