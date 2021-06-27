#include <Arduino.h>
#include <WiFiNINA.h>
#include <SPI.h>
#include <ArduinoHttpClient.h>

#include "arduino_secrets.h"

void printWifiStatus();

//#################################################################################################################################################

char hex[256];
uint8_t data[256];
int start = 0;
int seconds = 0;
uint8_t hash[32];
String pin;
#define SHA256_BLOCK_SIZE 32

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  unsigned long long bitlen;
  uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
  for ( ; i < 64; ++i)
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a,b,c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
  uint32_t i;

  for (i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
  uint32_t i;

  i = ctx->datalen;

  // Pad whatever data is left in the buffer.
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  }
  else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  // Append to the padding the total message's length in bits and transform.
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);

  // Since this implementation uses little endian byte ordering and SHA uses big endian,
  // reverse all the bytes when copying the final state to the output hash.
  for (i = 0; i < 4; ++i) {
    hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
  }
}

char *btoh(char *dest, uint8_t *src, int len) {
  char *d = dest;
  while( len-- ) sprintf(d, "%02x", (unsigned char)*src++), d += 2;
  return dest;
}

String SHA256(String data) 
{
  uint8_t data_buffer[data.length()];
  
  for(int i=0; i<data.length(); i++)
  {
    data_buffer[i] = (uint8_t)data.charAt(i);
  }
  
  SHA256_CTX ctx;
  ctx.datalen = 0;
  ctx.bitlen = 512;
  
  sha256_init(&ctx);
  sha256_update(&ctx, data_buffer, data.length());
  sha256_final(&ctx, hash);
  return(btoh(hex, hash, 32));
}



//#################################################################################################################################################





///////please enter your sensitive data in the Secret tab/arduino_secrets.h
char ssid[] = SECRET_SSID;        // your network SSID (name)
char pass[] = SECRET_PASS;    // your network password (use for WPA, or use as key for WEP)
int keyIndex = 0;            // your network key index number (needed only for WEP)

int status = WL_IDLE_STATUS;
// if you don't want to use DNS (and reduce your sketch size)
// use the numeric IP instead of the name for the server:
//IPAddress server(74,125,232,128);  // numeric IP for Google (no DNS)
char server[] = "192.168.1.1";    // name address for Google (using DNS)

// Initialize the Ethernet client library
// with the IP address and port of the server
// that you want to connect to (port 80 is default for HTTP):
WiFiClient wifi;
HttpClient client = HttpClient(wifi, server, 80);

void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your board's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}



// Number of milliseconds to wait without receiving any data before we give up
const int kNetworkTimeout = 30*1000;
// Number of milliseconds to wait if no data is available before trying again
const int kNetworkDelay = 1000;

String xmlobject;
String cookie = "SID=11caeaaf60cf4e4885c19e72a554992f52437548195a9ecc1b9e9f68df9c2a06";
char token[17];

void setup() {
  
    //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // check for the WiFi module:
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    // don't continue
    while (true);
  }

  String fv = WiFi.firmwareVersion();
  if (fv < WIFI_FIRMWARE_LATEST_VERSION) {
    Serial.println("Please upgrade the firmware");
  }

  // attempt to connect to WiFi network:
  while (status != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network. Change this line if using open or WEP network:
    status = WiFi.begin(ssid, pass);

    // wait 10 seconds for connection:
    delay(5000);
  }
  Serial.println("Connected to WiFi");
  printWifiStatus();


}

void loop() {

  int err =0;
  
  Serial.println("-----------------------------------------------------");
  Serial.println("|       request 1/7    arxiki selida                |");
  Serial.println("-----------------------------------------------------");
  
  client.beginRequest();
  err = client.get("/");
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();

  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);

        if ((cookie == "") && (headerName == "Set-Cookie")){
          cookie = headerValue.substring(1, 68);
          Serial.println("cookie : " + cookie );
        }
          
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              c = client.read();
              //Serial.print(c);

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();

  Serial.println("-----------------------------------------------------");
  Serial.println("|       request 2/7    xobject                      |");
  Serial.println("-----------------------------------------------------");
  
  client.beginRequest();
  err = client.get("/function_module/login_module/login_page/logintoken_lua.lua?_=1624612900537");
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();

  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              client.readStringUntil('>');
              xmlobject = client.readStringUntil('<');
              Serial.println("xmlobject = " + xmlobject);
              client.readStringUntil('\n');

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();

  //encrypt password
  String password = SECRET_PASSWORD + xmlobject;
  Serial.println("password = " + password);

  
  String password_sha256 = SHA256(password);
  Serial.println("encrypted password = " + password_sha256);

  String tmp = SECRET_USERNAME;
  String postData = "Username=" + tmp + "&Password=" + password_sha256 + "&action=login";
  Serial.println("postData = " + postData);

  Serial.println("-----------------------------------------------------");
  Serial.println("|       request 3/7    post request                 |");
  Serial.println("-----------------------------------------------------");
 
  client.beginRequest();
  err = client.post("/");
  client.sendHeader(HTTP_HEADER_CONTENT_TYPE, "application/x-www-form-urlencoded");
  client.sendHeader(HTTP_HEADER_CONTENT_LENGTH, postData.length());
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();
  client.write((const byte*)postData.c_str(), postData.length());
  
  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              c = client.read();
              //Serial.print(c);

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();

  Serial.println("-----------------------------------------------------");
  Serial.println("|       request 4/7    main menu                    |");
  Serial.println("-----------------------------------------------------");

  client.beginRequest();
  err = client.get("/");
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();

  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);

        if ((cookie == "") && (headerName == "Set-Cookie")){
          cookie = headerValue.substring(1, 68);
          Serial.println("cookie : " + cookie );
        }
          
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              c = client.read();
              //Serial.print(c);

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();

  Serial.println("--------------------------------------------------------------");
  Serial.println("|       request 5/7    select Managment tab                   |");
  Serial.println("--------------------------------------------------------------");

  client.beginRequest();
  err = client.get("/getpage.lua?pid=123&nextpage=ManagDiag_StatusManag_t.lp&Menu3Location=0&_=1624535491068");
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();

  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);

        if ((cookie == "") && (headerName == "Set-Cookie")){
          cookie = headerValue.substring(1, 68);
          Serial.println("cookie : " + cookie );
        }
          
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              c = client.read();
              //Serial.print(c);

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();

  Serial.println("------------------------------------------------------------------");
  Serial.println("|       request 6/7    select system managment                   |");
  Serial.println("------------------------------------------------------------------");

  client.beginRequest();
  err = client.get("/getpage.lua?pid=123&nextpage=ManagDiag_DeviceManag_t.lp&Menu3Location=0&_=1624535573870");
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();

  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);

        if ((cookie == "") && (headerName == "Set-Cookie")){
          cookie = headerValue.substring(1, 68);
          Serial.println("cookie : " + cookie );
        }
          
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {

        
          if (client.available())
          {

            String sessionTmpToken;

            //read one line from the html page
            String line = client.readStringUntil('\n');
            Serial.println(line);

            if (line.indexOf("_sessionTmpToken = \"") > -1 ){

              sessionTmpToken = line.substring(line.indexOf('\"') + 1, line.lastIndexOf('\"'));

              Serial.println("sessionTmpToken = " + sessionTmpToken);

              //for (size_t i = 0; i < sessionTmpToken.length(); i++)
              //{
              //  token[i] = sessionTmpToken[3 + i*4];
              //}

              int i = 0;
              while(i < 16)
              {
                token[i] = sessionTmpToken[3 + i*4];
                i++;
              }
              
              Serial.println(String("token = ") + token);
            }
            timeoutStart = millis();
          }
          else
          {   
              Serial.println("delayyyyy");
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();



  Serial.println("-----------------------------------------------------");
  Serial.println("|       request 7/7    post restart request         |");
  Serial.println("-----------------------------------------------------");

  postData = "IF_ACTION=Restart&Btn_restart=&_sessionTOKEN=" + String(token);
  Serial.println("postData = " + postData);
 
  client.beginRequest();
  err = client.post("/common_page/deviceManag_lua.lua");
  client.sendHeader(HTTP_HEADER_CONTENT_TYPE, "application/x-www-form-urlencoded");
  client.sendHeader(HTTP_HEADER_CONTENT_LENGTH, postData.length());
  client.sendHeader("Cookie", cookie + "; _TESTCOOKIESUPPORT=1");
  client.endRequest();
  client.write((const byte*)postData.c_str(), postData.length());
  
  if (err == 0)
  {
    Serial.println("startedRequest ok");

    err = client.responseStatusCode();
    if (err >= 0)
    {
      Serial.print("Got status code: ");
      Serial.println(err);

      while(client.headerAvailable())
      {
        String headerName = client.readHeaderName();
        String headerValue = client.readHeaderValue();
        Serial.println(headerName + " : " + headerValue);
      }

      int bodyLen = client.contentLength();
      Serial.print("Content length is: ");
      Serial.println(bodyLen);
      Serial.println();
      Serial.println("Body returned follows:");
    
      // Now we've got to the body, so we can print it out
      unsigned long timeoutStart = millis();
      char c;
      // Whilst we haven't timed out & haven't reached the end of the body
      while ( (client.connected() || client.available()) &&
             (!client.endOfBodyReached()) &&
             ((millis() - timeoutStart) < kNetworkTimeout) )
      {
          if (client.available())
          {
              c = client.read();
              //Serial.print(c);

              timeoutStart = millis();
          }
          else
          {
              delay(kNetworkDelay);
          }
      }
    }
    else
    {    
      Serial.print("Getting response failed: ");
      Serial.println(err);
    }
  }
  else
  {
    Serial.print("Connect failed: ");
    Serial.println(err);
  }
  client.stop();





  Serial.println("xxxxxxxxxxxxxxxxxxxxxxxxxx");

  // And just stop, now that we've tried a download
  while(1);
}


