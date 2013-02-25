var net = require('net');
var client = net.connect({port: 8080}, function() {
    var token = "<INSERT_YOUR_APNS_DEVICE_TOKEN>";
    var payload = new Buffer('{"aps":{"alert":"Hello World", "badge":1}}', 'utf8');
    var payload_len = payload.length;

    var buf = new Buffer(32 + 2 + 256);
    var p = 0;
    for(var i=0; i<32; ++i){
        buf.writeUInt8(parseInt(token.substr(i*2, 2), 16), i)
        p++;
    }

    buf.writeUInt16BE(payload_len, p);
    p +=2;
    payload.copy(buf, p);

    client.write(buf);
});
