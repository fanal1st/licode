using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace LicodeNavyClient
{
    /// <summary>
    /// licode nave cs client 
    /// </summary>
    public class Nuve
    {
        string _service;

        public string Service
        {
            get { return _service; }
            set { _service = value; }
        }
        string _key;

        public string Key
        {
            get { return _key; }
            set { _key = value; }
        }

        string _url;

        public string Url
        {
            get { return _url; }
            set { _url = value; }
        }
        int _port;

        public int Port
        {
            get { return _port; }
            set { _port = value; }
        }
        public Nuve(string service, string key, string url, int port)
        {
            _service = service;
            _key = key;
            _url = url;
            _port = port;
        }

        public string createRoom(string name, string options)
        {
            var response = send("POST", "{\"name\": \"" + name + "\", \"options\": \"" + options + "\"}", "/rooms/");
            return response;
        }

        public string getRooms()
        {
            var response = send("GET", null, "/rooms/");
            return response;
        }

        public string getRoom(string room)
        {
            var response = send("GET", null, "/rooms/" + room);
            return response;
        }

        public string deleteRoom(string room)
        {
            var response = send("DELETE", null, "/rooms/" + room);
            return response;
        }

        public string createToken(string room, string username, string role)
        {
            var response = send("POST", "{}", "/rooms/" + room + "/tokens", username, role);
            return response;
        }

        public string createService(string name, string key)
        {
            var response = send("POST", "{\"name\": \"" + name + "\", \"key\": \"" + key + "\"}", "/services/");
            return response;
        }

        public string getServices()
        {
            var response = send("GET", null, "/services/");
            return response;
        }

        public string getService(string service)
        {
            var response = send("GET", null, "/services/" + service);
            return response;
        }

        public string deleteService(string service)
        {
            var response = send("DELETE", null, "/services/" + service);
            return response;
        }

        public string getUsers(string room)
        {
            var response = send("GET", null, "/rooms/" + room + "/users/");
            return response;
        }

        public string getUser(string room, string user)
        {
            var response = send("GET", null, "/rooms/" + room + "/users/" + user);
            return response;
        }

        public string deleteUser(string room, string user)
        {
            var response = send("DELETE", null, "/rooms/" + room + "/users/" + user);
            return response;
        }



        private string send(string method, string body, string url, string username = "", string role = "")
        {
            var timestamp = (Int64)Grape.Common.Text.TimeManager.ConvertDateTimeInt(DateTime.Now);
            timestamp = timestamp * 1000;
            var cnounce = new Random().Next(99999);
            var toSign = timestamp + "," + cnounce.ToString("00000");
            var header = "MAuth realm=http://marte3.dit.upm.es,mauth_signature_method=HMAC_SHA1";
            if (username != "" && role != "")
            {
                header += ",mauth_username=";
                header += username;
                header += ",mauth_role=";
                header += role;
                toSign += "," + username + "," + role;
            }
            var signed = HmacSha1(_key, toSign);
            header += ",mauth_serviceid=";
            header += _service;
            header += ",mauth_cnonce=";
            header += cnounce.ToString("00000");
            header += ",mauth_timestamp=";
            header += timestamp;
            header += ",mauth_signature=";
            header += signed;

            string str = string.Empty;
            try
            {
                var uri = new Uri(string.Format("http://{0}:{1}{2}", _url, _port, url));
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
                request.Timeout = 15000;
                request.Method = method;
                request.Headers.Add("Authorization", header);
                request.ContentType = "application/json";
                if (body != null)
                {
                    byte[] bytes = Encoding.Default.GetBytes(body);
                    request.ContentLength = bytes.Length;
                    Stream requestStream = request.GetRequestStream();
                    requestStream.Write(bytes, 0, bytes.Length);
                    requestStream.Close();
                }
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    str = "{\"mess\":\"401.Unauthorized\",\"code\":401}";
                }
                using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.Default))
                {
                    str = reader.ReadToEnd().ToString();
                }
                response.Close();
            }
            catch (Exception ex)
            {
                str = "{\"mess\":\"" + ex.Message + "\",\"code\":-5}";
            }
            return str;
        }

        public static string HmacSha1(string key,string input)
        {
            byte[] keyBytes = ASCIIEncoding.ASCII.GetBytes(key);
            byte[] inputBytes = ASCIIEncoding.ASCII.GetBytes(input);
            HMACSHA1 hmac = new HMACSHA1(keyBytes);
            byte[] hashBytes = hmac.ComputeHash(inputBytes);
            var hexstr=BitConverter.ToString(hashBytes);
            Byte[] bts = Encoding.ASCII.GetBytes(hexstr);
            string innerstr = Convert.ToBase64String(bts);
            return innerstr;
        }



    }
}
