请求根目录
返回正确，但是奇怪的是Nginx没有直接返回包
而是给1.81的客户端先返回了一个seq=1,ack=365的小包

然后才开始传送实际的HTTP应答....

GET / HTTP/1.1
Host: audits.wukong.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/536.26.17 (KHTML, like Gecko) Version/6.0.2 Safari/536.26.17
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cache-Control: max-age=0
Accept-Language: zh-cn
Accept-Encoding: gzip, deflate
Connection: keep-alive

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 29 Jan 2013 04:42:24 GMT
Content-Type: text/html
Content-Length:5946
Last-Modified: Tue, 29 Jan 2013 04:42:01 GMT
Connection: keep-alive
Accept-Ranges: bytes

<html><head><meta http-equiv='pragma' content='no-cache'><meta http-equiv='cache-control' content='no-cache,must-revalidate'></head><body><h1>hhhhhhhhhhhh</h1><iframe width='1000' border='0' height='700' src='http://info.wukong.com/'></iframe></body></html>
.ewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="">

    <!-- Le styles -->
    <link href="css/bootstrap.css" rel="stylesheet">
    <style type="text/css">
      body {
        padding-top: 40px;
        padding-bottom: 40px;
        background-color: #f5f5f5;
      }

      .form-signin {
        max-width: 300px;
        padding: 19px 29px 29px;
        margin: 0 auto 20px;
        background-color: #fff;
        border: 1px solid #e5e5e5;
        -webkit-border-radius: 5px;
           -moz-border-radius: 5px;
                border-radius: 5px;
        -webkit-box-shadow: 0 1px 2px rgba(0,0,0,.05);
           -moz-box-shadow: 0 1px 2px rgba(0,0,0,.05);
                box-shadow: 0 1px 2px rgba(0,0,0,.05);
      }
      .form-signin .form-signin-heading,
      .form-signin .checkbox {
        margin-bottom: 10px;
      }
      .form-signin input[type="text"],
      .form-signin input[type="password"] {
        font-size: 16px;
        height: auto;
        margin-bottom: 15px;
        padding: 7px 9px;
      }

    </style>
    <link href="css/bootstrap-responsive.css" rel="stylesheet">

  </head>

  <body>
    <script src="js/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <script src="js/angular.min.js"></script>
    <script src="js/angular-resource.min.js"></script>
    
    <script src="users.js"></script>
  
  <div ng-controller="UserCtrl">
    <div class="container">

      <div class="form-signin">
        <h2 class="form-signin-heading">.........</h2>
        <input id="username" ng-model="username" type="text" class="input-block-level" placeholder=".............">
        <input id="password" ng-model="password" type="password" class="input-block-level" placeholder=".........">
        <!--
        <label class="checkbox">
          <input type="checkbox" value="remember-me"> Remember me
        </label>
   .. -->
        <button id="login_btn" class="btn btn-large btn-primary" ng-click="verfy_user()">......</button>
      </div>

    </div> <!-- /container -->

</div><!--End of UserCtrl-->
  </body>
</html>
GET /css/bootstrap.css HTTP/1.1
Host: audits.wukong.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/536.26.17 (KHTML, like Gecko) Version/6.0.2 Safari/536.26.17
Accept: text/css,*/*;q=0.1
If-Modified-Since: Thu, 07 Mar 2013 11:02:26 GMT
Cache-Control: max-age=0
If-None-Match: "127247-1362654146000"
Referer: http://audits.wukong.com/
Accept-Language: zh-cn
Accept-Encoding: gzip, deflate
Connection: keep-alive

HTTP/1.1 304 Not Modified
Server: nginx/1.3.14
Date: Tue, 12 Mar 2013 04:50:20 GMT
Connection: keep-alive
X-Powered-By: Express
Accept-Ranges: bytes
ETag: "127247-1362654146000"
Cache-Control: public, max-age=0
Last-Modified: Thu, 07 Mar 2013 11:02:26 GMT

GET /users.js HTTP/1.1
Host: audits.wukong.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/536.26.17 (KHTML, like Gecko) Version/6.0.2 Safari/536.26.17
Accept: */*
If-Modified-Since: Thu, 07 Mar 2013 11:02:26 GMT
Cache-Control: max-age=0
If-None-Match: "1134-1362654146000"
Referer: http://audits.wukong.com/
Accept-Language: zh-cn
Accept-Encoding: gzip, deflate
Connection: keep-alive

HTTP/1.1 304 Not Modified
Server: nginx/1.3.14
Date: Tue, 12 Mar 2013 04:50:20 GMT
Connection: keep-alive
X-Powered-By: Express
Accept-Ranges: bytes
ETag: "1134-1362654146000"
Cache-Control: public, max-age=0
Last-Modified: Thu, 07 Mar 2013 11:02:26 GMT