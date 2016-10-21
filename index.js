require('newrelic');
var express = require('express');
var app = express();
var cookieParser = require('cookie-parser');
var session = require('express-session');
var jsforce = require('jsforce');
var bodyParser = require('body-parser');
var pg = require('pg');
var CronJob = require('cron').CronJob;
var flash = require('connect-flash');
var passport = require('passport');
var SamlStrategy = require('passport-azure-ad').SamlStrategy;
var expressValidator = require('express-validator');
var fs = require('fs');
var http = require('http');
var https = require('https');
var CronJob = require('cron').CronJob;
var mainConfig = require('config');

var urlencodedParser = bodyParser.urlencoded({ extended: false });

var conn = null;
var oauth2 = null;

var conString = mainConfig.get('main.dbConfig.url');
var identifier = mainConfig.get('main.dbConfig.identifier');

app.set('port', process.env.PORT || 5000);
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(session({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
app.use(bodyParser.urlencoded({ extended : true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(__dirname + '/public'));
app.use(expressValidator());
app.use(flash());

var samlStrategy = null;

var getNewConnectionForAuth = function(request, response, next){

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        if(result.rowCount != 0){

	        var row = result.rows[0];

	        oauth2 = new jsforce.OAuth2({
			  	loginUrl: row.loginurl,
			    clientId : row.clientid,
			    clientSecret : row.clientsecret,
			    redirectUri : row.redirecturi
			});

			return next();
        }
        else{
        	request.flash('error','No Client id or Client secret found, Please specify them first !');
			response.locals.flash = request.flash();
		  	response.locals.layout = false;
        	response.render('pages/error');
        }

    }); 
}

function getNewConnection(request, response, next){

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        if(result.rowCount != 0){
	        var row = result.rows[0];

	        conn = new jsforce.Connection({
			  oauth2 : {
			  	loginUrl: row.loginurl,
			    clientId : row.clientid,
			    clientSecret : row.clientsecret,
			    redirectUri : row.redirecturi
			  },
			  instanceUrl : row.instanceurl,
			  accessToken : row.accesstoken,
			  refreshToken : row.refreshtoken
			});

			return next();
		}
		else{
			request.flash('error','No Client id or Client secret found, Please specify them first !');
			response.locals.flash = request.flash();
		  	response.locals.layout = false;
        	response.render('pages/error');
		}	
    });
}

var users = [];

var findByEmail = function(email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

var ensureAuthenticated = function(req, res, next) {
	console.log(req.isAuthenticated());
	if(samlStrategy != null){
	
	  if (req.isAuthenticated()) {
	    return next();
	  }
	  res.redirect('/login');
	}
	else{
		res.redirect('/');
	}  
};

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/lead/add',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
  	console.log('------------ redirect to lead');
    res.redirect('/lead');
  }
);

app.post('/logout/callback', function(req, res){
  console.log("logout post from:" + req.ip);
  res.redirect('/');
});

app.get('/logout', function(req, res){

  req.logout();
  res.redirect('/');
});

app.get('/identity', function(req, res){
  samlStrategy.identity(function(err, data) {
    if(err) {
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/html");
      res.end(err.message);
    } else {
      res.writeHead(200, {'Content-Type': 'application/xml'});
      res.end(data);
      var path = PATH.join(__dirname, 'federationmetadata.xml');
      fs.writeFileSync(path,data);
    }
  });
});

app.post('/run', function(req, res){

	var client = new pg.Client(conString);
    client.connect();
    var queryazuresso = client.query('CREATE TABLE azuresso(id serial NOT NULL,identitymetadata text,logincallback text,logoutcallback text,issuer text,appurl text,identifier text,CONSTRAINT identifier_unique_azuresso UNIQUE (identifier))');
    queryazuresso.on("end", function (result) {          
        //client.end();
        console.log('query azuresso success');
        var querysalesforcredentials = client.query('CREATE TABLE salesforcredentials(clientid text,clientsecret text,accesstoken text,instanceurl text,refreshtoken text,userid text,organizationid text,id serial NOT NULL,redirecturi text,loginurl text,identifier text,CONSTRAINT identifier_unique_salesforcredentials UNIQUE (identifier))');
	    querysalesforcredentials.on("end", function (result) {          
	        //client.end();
	        console.log('query salesforcredentials success');

	        var querysettingscredentials = client.query('CREATE TABLE settingscredentials(id serial NOT NULL,username text,password text,identifier text,CONSTRAINT username_unique UNIQUE (username),CONSTRAINT identifier_unique_settingscredentials UNIQUE (identifier))');
		    querysettingscredentials.on("end", function (result) {          
		        //client.end();
		        console.log('query settingscredentials success');

		        var queryinsert1 = client.query('INSERT INTO azuresso(identifier) VALUES (\''+identifier+'\')');
			    queryinsert1.on("end", function (result) {          
			        //client.end();
			        console.log('insert azuresso success');

			        var queryinsert2 = client.query('INSERT INTO salesforcredentials(identifier) VALUES (\''+identifier+'\')');
				    queryinsert2.on("end", function (result) {          
				        //client.end();
				        console.log('insert salesforcredentials success');

				        var queryinsert3 = client.query('INSERT INTO settingscredentials(username, password, identifier) VALUES ( \'admin\', \'admin123\', \''+identifier+'\')');
					    queryinsert3.on("end", function (result) {          
					        //client.end();
					        console.log('insert salesforcredentials success');

					        var queryareaofinterest = client.query('CREATE TABLE areaofinterest(id serial NOT NULL,interestcategory text,CONSTRAINT unique_interestc UNIQUE (interestcategory))');
						    queryareaofinterest.on("end", function (result) {          
						        //client.end();
						        console.log('query areaofinterest success');

						        var querycommencingstudy = client.query('CREATE TABLE commencingstudy(commencing_study text,id serial NOT NULL,CONSTRAINT unique_commencingstudy UNIQUE (commencing_study))');
							    querycommencingstudy.on("end", function (result) {          
							        //client.end();
							        console.log('query commencingstudy success');

							        var querytakiwa = client.query('CREATE TABLE takiwa(name text,id serial NOT NULL,CONSTRAINT unique_name_takiwa UNIQUE (name))');
								    querytakiwa.on("end", function (result) {          
								        client.end();
								        console.log('query takiwa success');
								        res.redirect('/settings');
								    });
							    });
						    });
					    });
				    });
			    });
		    });

		    querysettingscredentials.on("error", function (err, result) {          
		        client.end();
		        console.log(err);
		    }); 
	        
	    });

	    querysalesforcredentials.on("error", function (err, result) {          
	        client.end();
	        console.log(err);
	    });  
        
    });
    queryazuresso.on("error", function (err, result) {          
        client.end();
        console.log(err);
    });    
});


app.get('/', function(req, res){
	console.log('userrrrrr'+req.user);

	if(samlStrategy == null){

		var client_main = new pg.Client(conString);
		client_main.connect();

		var query_main = client_main.query("SELECT EXISTS (SELECT 1 FROM  information_schema.tables WHERE table_schema = 'public')");
		query_main.on("row", function (row, result) { 
		    result.addRow(row);
		});

		query_main.on("end", function (result) { 
		    client_main.end();

		    var row = result.rows[0];

		    if(!row.exists){
		    	res.render('pages/install_script');
		    }
		    else{
		    	var client_for_config = new pg.Client(conString);
				client_for_config.connect();
				var query_for_config = client_for_config.query('select * from public.azuresso where identifier = \''+identifier+'\'');
				query_for_config.on("row", function (row, result) { 
				    result.addRow(row);
				});
				query_for_config.on("end", function (result) {          
				    client_for_config.end();

				    var row = result.rows[0];

				    if(row && row.identitymetadata){
					    console.log('identitymetadata='+row.identitymetadata);
					    console.log('logincallback='+row.logincallback);
					    console.log('logoutcallback='+row.logoutcallback);
					    console.log('issuer='+row.issuer);
					    console.log('appurl='+row.appurl);

					    var config = {

						  identityMetadata: row.identitymetadata,
						  loginCallback: row.logincallback,
						  logoutCallback: row.logoutcallback,
						  issuer: row.issuer,
						  appUrl: row.appurl,

						  privateCert: fs.readFileSync('./private.pem', 'utf-8'),
						  publicCert: fs.readFileSync('./public.pem', 'utf-8'),
						};

						samlStrategy = new SamlStrategy(config, function(profile, done) {
						console.log(profile);
						    if (!profile.email) {
						      return done(new Error("No email found"), null);
						    }
						    process.nextTick(function () {
						      findByEmail(profile.email, function(err, user) {
						        if (err) {
						          return done(err);
						        }
						        if (!user) {
						          // "Auto-registration"
						          users.push(profile);
						          return done(null, profile);
						        }
						        return done(null, user);
						      });
						    });
						  }
						);

						passport.use(samlStrategy);
						res.redirect('/lead');
				    }
				    else{
				    	res.redirect('/settings');
				    }
				});
		    }
		});
	}
	else{
		if(req.user) {
  			res.redirect('/lead');
	  	} else {
	    	res.render('pages/index', { user: req.user });
	  	}
	}
});

var server = http.createServer(app).listen(app.get('port'), function(){
  console.log("Node app is running on port " + app.get('port'));
});

passport.serializeUser(function(user, done) {
  done(null, user.email);
});

passport.deserializeUser(function(id, done) {
  findByEmail(id, function (err, user) {
    done(err, user);
  });
});

server.timeout = 200000;

function checkSettingsAuth (req, res, next) {

    if(req.session.isSettingsAuth == true){
    	return next();
    }
    return res.redirect('/settings_login');
}

app.get('/settings_login', function(request, response) {

	if(request.session.isSettingsAuth == true){
    	return response.redirect('/settings');
    }
    else{
    	return response.render('pages/settings_login', {data : null});	
    }
});

app.get('/settings_logout', function(request, response) {

	request.session.isSettingsAuth = false;
    return response.redirect('/settings_login');
});

app.post('/settings_logout', function(request, response) {

	request.session.isSettingsAuth = false;
    return response.redirect('/settings_login');
});

app.post('/settings_login', urlencodedParser, function(request, response) {

	request.assert('username', 'Username is required').notEmpty();
	request.assert('password', '6 to 20 characters required for password').len(6, 20);

	var data_on_error = {username: request.body.username};

	var validation_errors = request.validationErrors();

	if(!validation_errors){

		var client = new pg.Client(conString);
	    client.connect();
	    var query = client.query('select * from public.settingscredentials where identifier = \''+identifier+'\'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          
	        client.end();
	        
	        var row = result.rows[0];
			if(request.body.username === row.username && request.body.password === row.password){
				request.session.isSettingsAuth = true;
				return response.redirect('/settings');
			}
			else{
				request.session.isSettingsAuth = false;
				request.flash('error','Wrong username or password !');
				response.locals.flash = request.flash();
			  	response.locals.layout = false;
				response.render('pages/settings_login', {data: data_on_error});
			}

		});
	}
	else{
		response.render('pages/settings_login', {data: data_on_error, validation_errors: validation_errors});
	}
});

app.get('/settings', function(request, response) {

	checkSettingsAuth(request, response, function(){
		var client = new pg.Client(conString);
	    client.connect();
	    var query = client.query("select * from public.salesforcredentials, public.azuresso, public.settingscredentials");
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          
	        client.end();
	        response.render('pages/settings', {data : result.rows[0]});
	    }); 
	})
});

app.post('/settings', urlencodedParser, function(request, response) {

	checkSettingsAuth(request, response, function(){
		if(request.body.tab_posted == 'salesforce'){

			request.assert('clientid', 'Client id is required').notEmpty();
			request.assert('clientsecret', 'Client secret is required').notEmpty();
			request.assert('loginurl', 'Login URL is required').notEmpty();
			request.assert('redirecturi', 'Redirect URI is required').notEmpty();

			var data_on_error = {clientid: request.body.clientid, clientsecret: request.body.clientsecret, loginurl: request.body.loginurl, redirecturi: request.body.redirecturi};

			var validation_errors = request.validationErrors();

			if(!validation_errors){

				console.log('validation_errors passed');

				var client = new pg.Client(conString);
			    client.connect();
			    var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
			    query.on("row", function (row, result) { 
			        result.addRow(row); 
			    });
			    query.on("end", function (result) {          

			        if(result.rowCount != 0){

				        var query_update = client.query('update salesforcredentials set clientid=$1, clientsecret=$2, redirecturi=$3, loginurl=$4 where identifier =$5', [request.body.clientid, request.body.clientsecret, request.body.redirecturi, request.body.loginurl, identifier]);    
				        query_update.on("end", function (result) {          
				            client.end(); 
				            request.flash('success', 'Settings saved successfully !');
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            loadSettingsAfterSave(request, response);
				        });

				        query_update.on("error", function (err, result) {  
				        	client.end();
			        		request.flash('error',err);
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.render('pages/settings', {data: data_on_error});
				        });   
			        }
			        else{

			        	console.log('update data');
			        	
			        	var query_insert = client.query('insert into salesforcredentials (clientid,clientsecret,redirecturi,loginurl,identifier) values($1, $2, $3, $4, $5)', [request.body.clientid, request.body.clientsecret, request.body.redirecturi, request.body.loginurl, identifier]);    
				        query_insert.on("end", function (result) {   
				        	console.log('update data success');       
				            client.end(); 
				            request.flash('success','Settings saved successfully !');
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            loadSettingsAfterSave(request, response);
				        });

				        query_insert.on("error", function (err, result) {  
				        	client.end();
			        		request.flash('error',err);
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.render('pages/settings', {data: data_on_error});
				        });    
			        }
			    }); 
			}
			else{
				response.render('pages/settings', {data: data_on_error, validation_errors: validation_errors});
			}

		}
		else if(request.body.tab_posted == 'sso'){
			request.assert('identitymetadata', 'Identity metadata is required').notEmpty();
			request.assert('logincallback', 'Login callback is required').notEmpty();
			request.assert('appurl', 'App url is required').notEmpty();

			var data_on_error = {identitymetadata: request.body.identitymetadata, logincallback: request.body.logincallback, logoutcallback: request.body.logoutcallback, issuer: request.body.issuer, appurl: request.body.appurl};

			var validation_errors = request.validationErrors();

			if(!validation_errors){

				console.log('validation_errors passed');

				var client = new pg.Client(conString);
			    client.connect();
			    var query = client.query('select * from public.azuresso where identifier = \''+identifier+'\'');
			    query.on("row", function (row, result) { 
			        result.addRow(row); 
			    });
			    query.on("end", function (result) {          

			        if(result.rowCount != 0){

				        var query_update = client.query('update azuresso set identitymetadata=$1, logincallback=$2, logoutcallback=$3, issuer=$4, appurl=$5 where identifier=$6', [request.body.identitymetadata, request.body.logincallback, request.body.appurl+'/logout/callback', request.body.appurl, request.body.appurl, identifier]);    
				        query_update.on("end", function (result) {          
				            client.end(); 
				            request.flash('success', 'Settings saved successfully !');
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
						  	samlStrategy = null;
				            response.redirect('/');
				        });

				        query_update.on("error", function (err, result) {  
				        	client.end();
			        		request.flash('error',err);
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.render('pages/settings', {data: data_on_error});
				        });   
			        }
			        else{

			        	console.log('update data');
			        	
			        	var query_insert = client.query('insert into azuresso (identitymetadata,logincallback,logoutcallback,issuer,appurl,identifier) values($1, $2, $3, $4, $5, $6)', [request.body.identitymetadata, request.body.logincallback, request.body.appurl+'/logout/callback', request.body.appurl, request.body.appurl, identifier]);    
				        query_insert.on("end", function (result) {   
				        	console.log('update data success');       
				            client.end(); 
				            request.flash('success','Settings saved successfully !');
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.redirect('/');
				        });

				        query_insert.on("error", function (err, result) {  
				        	client.end();
			        		request.flash('error',err);
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.render('pages/settings', {data: data_on_error});
				        });    
			        }
			    }); 
			}
			else{
				response.render('pages/settings', {data: data_on_error, validation_errors: validation_errors});
			}
		}
		else if(request.body.tab_posted == 'settinglogin'){
			request.assert('newpassword', '6 to 20 characters required for password').len(6, 20);
			request.assert('currentpassword', 'Current password is required').notEmpty();

			var validation_errors = request.validationErrors();

			var data_on_error = null;

			var client_data = new pg.Client(conString);
			client_data.connect();
			var query_data = client_data.query('select * from public.salesforcredentials, public.azuresso, public.settingscredentials');
		    query_data.on("row", function (row, result) { 
		        result.addRow(row); 
		    });
		    query_data.on("end", function (result) {
		    	client_data.end();
		    	data_on_error = result.rows[0];

		    	if(!validation_errors){
					console.log('validation_errors passed');

					var client = new pg.Client(conString);
				    client.connect();
				    var query = client.query('select * from public.settingscredentials where identifier = \''+identifier+'\'');
				    query.on("row", function (row, result) { 
				        result.addRow(row); 
				    });
				    query.on("end", function (result) {          

				        if(result.rowCount != 0){

				        	var row = result.rows[0];

				        	if(row.password === request.body.currentpassword){
				        		var query_update = client.query('update settingscredentials set password=$1 where identifier=$2', [request.body.newpassword, identifier]);    
						        query_update.on("end", function (result) {          
						            client.end(); 
						            request.flash('success', 'Password changed successfully, Please login again !');
									response.locals.flash = request.flash();
								  	response.locals.layout = false;
						            loadSettingsLoginAfterSave(request, response);
						        });

						        query_update.on("error", function (err, result) {  
						        	client.end();
					        		request.flash('error',err);
									response.locals.flash = request.flash();
								  	response.locals.layout = false;
						            response.render('pages/settings', {data: data_on_error});
						        }); 
				        	}
				        	else{
				        		request.flash('error','Password not matched !');
								response.locals.flash = request.flash();
							  	response.locals.layout = false;
					            response.render('pages/settings', {data: data_on_error});
				        	}
				        }
				        else{
				        	
			        		request.flash('error','No record found');
							response.locals.flash = request.flash();
						  	response.locals.layout = false;
				            response.render('pages/settings', {data: data_on_error});
				        }
				    }); 
				}
				else{
					response.render('pages/settings', {data: data_on_error, validation_errors: validation_errors});
				}
		    });
		}
	})	
});

app.get('/lead', ensureAuthenticated, function(request, response) {

	getNewConnection(request, response, function(){

		if (conn == null) return response.render('pages/error');

		console.log('Loading lead page...');

		console.log('====================== lead get =========================')

		var data = [];

		conn.on("refresh", function(accessToken, res) {
			console.log('New accessToken='+accessToken);
			saveNewAccessToken(accessToken);
		});	

		conn.describe("Lead", function(err, meta) {
		  if (err) 
		  { 
		  	console.log('errrrrrrrrrrrrrr'+err);
		  	request.flash('error',err);
		  	response.locals.flash = request.flash();
	  	  	response.locals.layout = false;
		  	response.render('pages/error');
		  }
		  else{
			  var picklistValues = [];
			  meta.fields.forEach(function(field){
			  	if(field.name == 'Additional_Information_Type__c'){
			  		picklistValues = field.picklistValues;	
			  	}
			  })
			  data.push({additionalInformationTypes: picklistValues});

			  if(request.user){
			  	data.push({ user: request.user });	
			  }
			  else{
			  	data.push({ user: null });
			  }
			  response.render('pages/lead_add', {data: data});
		  }
		});

	})
});

app.get('/salesforce/oauth2/auth', function(req, res){

	getNewConnectionForAuth(req, res, function(){

		console.log('oauth2='+oauth2);

	    if(oauth2 == null){ return res.render('pages/error'); }

		res.redirect(oauth2.getAuthorizationUrl({ scope : 'api id web refresh_token' }));

	})

});

app.get('/salesforce/authentication/callback', function(req, res) {

	var code = req.param('code');

	if(code != null || code != ''){

		console.log('code='+code);

		getNewConnectionForAuth(req, res, function(){

			console.log('oauth2 oauth2='+oauth2);

	        if(oauth2 == null){ return res.render('pages/error'); }

	        var conn = new jsforce.Connection({ oauth2 : oauth2 });
		  	
		  	conn.authorize(code, function(err, userInfo) {
		    	if (err) { 
		    		console.error(err); 
		    		request.flash('error',err);
					response.locals.flash = request.flash();
					response.locals.layout = false;
		    		res.render('pages/error');
		    	}
		    	else{
		    		console.log(conn.accessToken);
			    	console.log(conn.refreshToken);
			    	console.log(conn.instanceUrl);
			    	console.log("User ID: " + userInfo.id);
			    	console.log("Org ID: " + userInfo.organizationId);

			    	var client = new pg.Client(conString);
		    		client.connect();

			    	var query_update = client.query('update salesforcredentials set accesstoken=$1, refreshtoken=$2, instanceurl=$3, userid=$4, organizationid=$5 where identifier =$6', [conn.accessToken, conn.refreshToken, conn.instanceUrl, userInfo.id, userInfo.organizationId, identifier]);    
			        query_update.on("end", function (result) {          
			            client.end(); 

			            refreshTokenScheduler();
			            salesforceDataScheduler();
			            loadSalesforceDataToDB();

					  	res.render('pages/salesforce_auth_success');
			            
			        });

			        query_update.on("error", function (err, result) {  
			        	client.end();
		        		request.flash('error',err);
						response.locals.flash = request.flash();
					  	response.locals.layout = false;
			            response.render('pages/error');
			        }); 

			    	
		    	}

		    	console.log('====================== after authentication =========================')
		  	});

		})
	}
	else{ 
		console.error('No code specified'); 
		req.flash('error','No code specified');
	  	res.locals.flash = req.flash();
  	  	res.locals.layout = false;
		res.render('pages/error'); 
	}
});

app.post('/lead', urlencodedParser, function(request, response) {

	getNewConnection(request, response, function(){

		request.assert('salutation', 'Salutation is required').notEmpty();
		request.assert('first_name', 'First name is required').notEmpty();
		request.assert('last_name', 'Last name is required').notEmpty();
		request.assert('takiwa_val', 'At least one takiwa in selected interest is required').notEmpty();
		request.assert('studyDetailsListTableDataJSON', 'At least one selected interest is required').notEmpty();

		var validation_errors = request.validationErrors();

		if(!validation_errors){

			var other_marketing_information_value = null;
			  if(request.body.other_marketing_information != '' && request.body.other_marketing_information != 'undefined' && request.body.other_marketing_information != null){
			  	other_marketing_information_value = request.body.other_marketing_information;
			  }

			  var kaimahi_value = null;
			  if(request.body.followupCallValueBy == 'Assigned EOI To Kaimahi'){
			  	kaimahi_value = request.body.kaimahiName;
			  }

			  var country_val = '';
			  if(typeof request.body.country !== 'undefined'){
			  	country_val = request.body.country;
			  }

			  var state_val = '';
			  if(typeof request.body.administrative_area_level_1 !== 'undefined'){
			  	state_val = request.body.administrative_area_level_1;
			  }

			  var city_val = '';
			  if(typeof request.body.locality !== 'undefined'){
			  	city_val = request.body.locality;
			  }

			  var postal_code_val = '';
			  if(typeof request.body.postal_code !== 'undefined'){
			  	postal_code_val = request.body.postal_code;
			  }

			  var street_number_val = '';
			  if(typeof request.body.street_number !== 'undefined'){
			  	street_number_val = request.body.street_number;
			  }

			  var route_val = '';
			  if(typeof request.body.route !== 'undefined'){
			  	route_val = request.body.route;
			  }

			  var date_of_Birth_val = null;
			  if(request.body.dob_year != '' && request.body.dob_month != '' && request.body.dob_day != '' && request.body.dob_year != 'undefined' && request.body.dob_month != 'undefined' && request.body.dob_day != 'undefined'){
			  	date_of_Birth_val = request.body.dob_year+'-'+request.body.dob_month+'-'+request.body.dob_day;
			  }
			  
			  conn.sobject("Lead").create(
					{ 
						Salutation : request.body.salutation,
						FirstName : request.body.first_name,  
						LastName : request.body.last_name, 
						Date_of_Birth__c : date_of_Birth_val,
						Company : '', 
						Email : request.body.email,
						Phone : request.body.area_code1+''+request.body.phone,
						Status : 'Open',
						Schedule_a_follow_up_by__c : request.body.followupCallValueBy,
						Schedule_a_follow_up_time__c : request.body.followupCallValueTime,
						Send_brochures__c : request.body.sendBrochuresValue,
						Followup_Timeframe__c : request.body.deliveryDaysValue,
						Description : request.body.additional_comment,
						LeadSource : 'Te Kupenga',
						Other_marketing_information__c : other_marketing_information_value,
						Country : country_val,
						State : state_val,
						City : city_val,
						PostalCode : postal_code_val,
						Street : street_number_val+' '+route_val,
						Kaiako_Kaimahi__c : kaimahi_value,
						Engagement_Method__c : request.body.enagement_method_value,
						Takiwa__c : request.body.takiwa_val,
						MobilePhone : request.body.area_code2+''+request.body.other_phone
					}, 
					function(err, ret) {
			  		if (err || !ret.success) {
			  		  request.flash('error',err);
					  response.locals.flash = request.flash();
				  	  response.locals.layout = false;
			  		  var data = [];
			  		  console.error(err, ret);
			  		  if(request.user){
					  	data.push({ user: request.user });	
					  }
					  else{
					  	data.push({ user: null });
					  }
			  		  data.push({error: err});
			  		  conn.describe("Lead", function(err, meta) {
						  if (err) 
						  { 
						  	console.log('errrrrrrrrrrrrrr'+err);
						  	response.render('pages/error');
						  }
						  else{
							  var picklistValues = [];
							  meta.fields.forEach(function(field){
							  	if(field.name == 'Additional_Information_Type__c'){
							  		picklistValues = field.picklistValues;	
							  	}
							  })
							 // console.log(picklistValues);
							  data.push({additionalInformationTypes: picklistValues});
							  response.render('pages/lead_add', {data: data});
						  }
						}); 
			  		}
			  		else{
			  			console.log("Created record id : " + ret.id);

			  			console.log('request.body.studyDetailsListTableDataJSON========='+request.body.studyDetailsListTableDataJSON);

			  			if(request.body.studyDetailsListTableDataJSON != '' && request.body.studyDetailsListTableDataJSON != null){

			  				var jsonData = JSON.parse(request.body.studyDetailsListTableDataJSON);
			  				jsonData.forEach(function(record){
			  					conn.sobject("Program_of_Interest__c").create(
						  		{ 
						  			Lead__c: ret.id,
						  			Program__c : record.programme,
						  			Region__c : record.location,
						  			Takiwa_TeKupenga__c : record.takiwa
						  		}, 
						  		function(err, ret) {
							  		if (err || !ret.success) {
							  		  console.error(err, ret); 
							  		  response.render('pages/lead_add');
							  		}
							  		else{
							  			console.log("Created record id Program_of_Interest__c : " + ret.id);
							  		}
								});
			  				})
			  			}

			  			if(request.body.additional_type.length != 0){
			  				for (var i = 0; i < request.body.additional_type.length; i++) {
			  				
				  				conn.sobject("Additional_information__c").create(
						  		{ 
						  			Lead__c: ret.id,
						  			Name : request.body.additional_type[i],
						  			Value__c : request.body.additionalInformationTypeInput[i]
						  		}, 
						  		function(err, ret) {
							  		if (err || !ret.success) {
							  		  console.error(err, ret); 
							  		  response.render('pages/lead_add');
							  		}
							  		else{
							  			console.log("Created record id Additional_information__c : " + ret.id);
							  			console.log("request.body.additional_type.length : " + request.body.additional_type.length +"   i:"+i);
							  		}
								});
				  			};
			  			}

			  			if(request.body.campaigns != '' && request.body.campaigns != null){
			  				
			  				conn.sobject("CampaignMember").create(
					  		{ 
					  			LeadId: ret.id,
					  			CampaignId : request.body.campaigns
					  		}, 
					  		function(err, ret) {
						  		if (err || !ret.success) {
						  		  console.error(err, ret); 
						  		  response.render('pages/lead_add');
						  		}
						  		else{
						  			console.log("Created record id CampaignMember : " + ret.id);
						  		}
							});
			  			}
			  			response.render('pages/lead_success');
			  		}
				});
		}
		else{
			  var data = [];
			  conn.describe("Lead", function(err, meta) {
			  if (err) 
			  { 
			  	console.log('errrrrrrrrrrrrrr'+err);
			  	response.render('pages/error');
			  }
			  else{
				  var picklistValues = [];
				  meta.fields.forEach(function(field){
				  	if(field.name == 'Additional_Information_Type__c'){
				  		picklistValues = field.picklistValues;	
				  	}
				  })
				 // console.log(picklistValues);
				  data.push({additionalInformationTypes: picklistValues});
				  if(request.user){
				  	data.push({ user: request.user });	
				  }
				  else{
				  	data.push({ user: null });
				  }
				  response.render('pages/lead_add', {data: data, validation_errors: validation_errors});
			  }
			}); 
		}
	})
});

app.post('/loadLocationData', urlencodedParser, function(req, res) {

	var takiwa = req.body.takiwa;

	var takiwa_val_condition = '';
	if(takiwa != '' && takiwa != null){
		takiwa_val_condition = ' where Takiwa__c = \''+takiwa+'\'';
	} 

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query('select sfid, name from salesforce.Region__c'+takiwa_val_condition+'');
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        var locations = [];
        result.rows.forEach(function(record){
		  	var location = {};
		  	location.label = record.name; 
		  	location.value = record.sfid; 
		  	locations.push(location);
		})
	  	locations.sort(function (a, b) {
		  if (a.label > b.label) {
		    return 1;
		  }
		  if (a.label < b.label) {
		    return -1;
		  }
		  return 0;
		});

        res.send(locations);
    });			
});

app.post('/loadCampaignData', urlencodedParser, function(req, res) {

	getNewConnection(req, res, function(){
		var takiwa = req.body.takiwa;

	   		if(conn == null){
	   			console.log('no refresh token found');
				res.send("Error " + err);
			}
			else{
				
				var campaigns = [];
				conn.query('SELECT Id, Name FROM Campaign where Status = \'In Progress\'', function(err, result) {
				  if (err) { return console.error(err); }
				  result.records.forEach(function(record){
				  	var campaign = {};
				  	campaign.label = record.Name; 
				  	campaign.value = record.Id; 
				  	campaigns.push(campaign);
				  })
				  	campaigns.sort(function (a, b) {
					  if (a.label > b.label) {
					    return 1;
					  }
					  if (a.label < b.label) {
					    return -1;
					  }
					  return 0;
					});
				  
				  //console.log('-----------campaigns'+campaigns);
				  res.send(campaigns);	

			});
		}		
	})	
});

app.post('/loadCommencingStudyData', function(req, res) {

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query("select * from public.commencingstudy");
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        var commencing_studys = [];
        result.rows.forEach(function(record){
		  	var commencing_study_val = {};
		  	commencing_study_val.label = record.commencing_study; 
		  	commencing_study_val.value = record.commencing_study; 
		  	commencing_studys.push(commencing_study_val);
		})

        res.send(commencing_studys);
    });
});

app.post('/loadAreaOfInterestData', function(req, res) {

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query("select * from public.areaofinterest");
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        var areaofinterests = [];
        result.rows.forEach(function(record){
		  	var areaofinterest = {};
		  	areaofinterest.label = record.interestcategory; 
		  	areaofinterest.value = record.interestcategory; 
		  	areaofinterests.push(areaofinterest);
		})

        res.send(areaofinterests);
    });
});

app.post('/loadProgrammeData', urlencodedParser, function(req, res) {

	var location_val = req.body.location;
	var area_of_interest_val = req.body.area_of_interest;

	var location_val_condition = '';
	var area_of_interest_val_condition = '';
	if(location_val != '' && location_val != null){
		location_val_condition = ' where Campus__c in (select sfid from salesforce.campus__c where Region__c = \''+location_val+'\')';
	} 
	if(area_of_interest_val != '' && area_of_interest_val != null){
		area_of_interest_val_condition = ' and Interest_Category__c = \''+area_of_interest_val+'\'';
	}

	if((location_val != '' && location_val != null) || (area_of_interest_val != '' && area_of_interest_val != null)){

		var client = new pg.Client(conString);
	    client.connect();
	    var query = client.query('select sfid, name from salesforce.Program__c where Active__c = true and sfid in (select Program__c from salesforce.Offered_Program__c'+location_val_condition+')'+area_of_interest_val_condition+'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          
	        client.end();

	        var programmes = [];
	        result.rows.forEach(function(record){
			  	var programme = {};
			  	programme.label = record.name;
			  	programme.value = record.sfid; 
			  	programmes.push(programme);
			})
		  	programmes.sort(function (a, b) {
			  if (a.label > b.label) {
			    return 1;
			  }
			  if (a.label < b.label) {
			    return -1;
			  }
			  return 0;
			});

	        res.send(programmes);
	    });
	}
	else{
		loadProgrammes(res);
	}
});

app.post('/loadKaiakoData', urlencodedParser, function(req, res) {

	getNewConnection(req, res, function(){

		var programme_id = req.body.Id;

		console.log('programme_id = '+programme_id);

		if(conn == null){
			console.log('no refresh token found');
			res.send("Error " + err);
		}
		else{
			
			var programme_lecturers = [];
			conn.query('select Program_Contact__c, Program_Contact__r.Name from Program__c where id = \''+programme_id+'\'', function(err, result) {
			  if (err) { return console.error(err); }
			  var programme_lecturer = {};
			  if(result.records.length != 0 && result.records[0].Program_Contact__c != null){
			  	programme_lecturer.name = result.records[0].Program_Contact__r.Name;
			  }
			  else{
			  	programme_lecturer.name = '';
			  }
			  
			  programme_lecturers.push(programme_lecturer);
			  res.send(programme_lecturers);
			});	
		}
	})			
});

app.post('/loadTakiwaData', function(req, res) {

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query("select * from public.takiwa");
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        var takiwas = [];
        result.rows.forEach(function(record){
		  	var takiwa = {};
		  	takiwa.label = record.name; 
		  	takiwa.value = record.name; 
		  	takiwas.push(takiwa);
		})

        res.send(takiwas);
    });
});

app.post('/loadAreaCodeData', function(req, res) {
	
	getNewConnection(req, res, function(){

		conn.describe("Lead", function(err, meta) {
		  if (err) 
		  { 
		  	console.log('errrrrrrrrrrrrrr'+err);
		  	req.flash('error',err);
		  	res.locals.flash = req.flash();
	  	  	res.locals.layout = false;
		  	res.render('pages/error');
		  }
		  else{
			  var picklistValues = [];
			  meta.fields.forEach(function(field){
			  	if(field.name == 'Phone_Codes__c'){
			  		picklistValues = field.picklistValues;	
			  	}
			  })
			  res.send(picklistValues);
		  }
		});
	})	
});

app.post('/loadKaimahiNameData', function(req, res) {

	getNewConnection(req, res, function(){

		if(conn == null){
			console.log('no refresh token found');
			res.send("Error " + err);
		}
		else{

			var kaimahi_names = [];
			var query = 'select Id, Name from Contact where type__c = \'Te Wananga Staff\'';
			conn.query(query, function(err, result) {
			  if (err) { return console.error(err); }
			  result.records.forEach(function(record){
			  	var kaimahi_name = {};
			  	kaimahi_name.label = record.Name; 
			  	kaimahi_name.value = record.Id; 
			  	kaimahi_names.push(kaimahi_name);
			  })
			  	kaimahi_names.sort(function (a, b) {
				  if (a.label > b.label) {
				    return 1;
				  }
				  if (a.label < b.label) {
				    return -1;
				  }
				  return 0;
				});
			  
			  res.send(kaimahi_names);
			});	
		}
	})				
});

app.post('/loadEngagementMethodData', function(req, res) {

	getNewConnection(req, res, function(){

		if(conn == null){
			console.log('no refresh token found');
			res.send("Error " + err);
		}
		else{
			
			var CommencingStudys = [];
			conn.describe("Lead", function(err, meta) {
			  if (err) 
			  { 
			  	console.log('errrrrrrrrrrrrrr'+err);
			  	res.send("Error " + err);
			  }
			  else{
				  var picklistValues = [];
				  meta.fields.forEach(function(field){
				  	if(field.name == 'Engagement_Method__c'){
				  		picklistValues = field.picklistValues;	
				  	}
				  })
				  picklistValues.sort(function (a, b) {
				  if (a.label > b.label) {
				    return 1;
				  }
				  if (a.label < b.label) {
				    return -1;
				  }
				  return 0;
				});
				  //console.log(picklistValues);
				  res.send(picklistValues);
			  }
			});
		}
	})			
});

function saveNewAccessToken(accessToken){

	var client = new pg.Client(conString);
	client.connect();

	var query_update = client.query('update salesforcredentials set accesstoken=$1 where identifier=$2', [accessToken, identifier]);    
    query_update.on("end", function (result) {          
        client.end(); 
        console.log('access token refreshed');
    });

    query_update.on("error", function (err, result) {  
    	client.end();
    	console.log('error='+err);
    }); 
}

function loadProgrammes(res){

	var client = new pg.Client(conString);
    client.connect();
    var query = client.query('select sfid, name from salesforce.Program__c where Active__c = true');
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();

        var programmes = [];
        result.rows.forEach(function(record){
		  	var programme = {};
		  	programme.label = record.name;
		  	programme.value = record.sfid; 
		  	programmes.push(programme);
		})
	  	programmes.sort(function (a, b) {
		  if (a.label > b.label) {
		    return 1;
		  }
		  if (a.label < b.label) {
		    return -1;
		  }
		  return 0;
		});

        res.send(programmes);
    });
}

function loadSettingsAfterSave(request, response){
	var client = new pg.Client(conString);
    client.connect();
    var query = client.query("select * from public.salesforcredentials, public.azuresso, public.settingscredentials");
    query.on("row", function (row, result) { 
        result.addRow(row); 
    });
    query.on("end", function (result) {          
        client.end();
        response.render('pages/settings', {data : result.rows[0]});
    }); 
}

function loadSettingsLoginAfterSave(request, response){
	request.session.isSettingsAuth = false;
	return response.render('pages/settings_login', {data : null});
}


function refreshTokenScheduler(){

	try {
	
		var job = new CronJob({
		  cronTime: '0 */10 * * * *',
		  onTick: function() {
		    
		    console.log('--------------------- refreshTokenScheduler -'+new Date()+' ----------------------');
		    refreshAccessToken();
		  },
		  start: true,
		  timeZone: 'Pacific/Auckland'
		});
		job.start();

	} catch(ex) {
		console.log(ex);
	}
}

function refreshAccessToken(){

	try{

		var client = new pg.Client(conString);
	    client.connect();
	    var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          
	        client.end();

	        if(result.rowCount != 0){

		        var row = result.rows[0];

		        var postData = 'grant_type=refresh_token&client_id='+row.clientid+'&client_secret='+row.clientsecret+'&refresh_token='+row.refreshtoken+'';
		        var hostname_val = row.instanceurl.split('//');

		       	var options = {
				  hostname: hostname_val[1],
				  path: '/services/oauth2/token',
				  method: 'POST',
				  headers: {
				    'Content-Type': 'application/x-www-form-urlencoded'
				  }
				};

				var req = https.request(options, function(res) {
					res.setEncoding('utf8');
					res.on('data', function (authresponse) {
					    var obj = JSON.parse(authresponse);
					    
					    saveNewAccessToken(obj.access_token);
						 
					});
					res.on('end', function() {
					    console.log('No more data in response.');
				  	});
				});

				req.on('error', function(e) {
				  console.log('problem with request: ' + e.message);
				});

				// write data to request body
				req.write(postData);
				req.end();
	        }
	        else{
	        	console.log('No Client id or Client secret found, Please specify them first !');
	        }

	    }); 

	} catch(ex) {
		console.log(ex);
	}
}

function salesforceDataScheduler(){

	try {
	
		var job = new CronJob({
		  cronTime: '0 */30 * * * *',
		  onTick: function() {
		    
		    console.log('--------------------- salesforceDataScheduler -'+new Date()+' ----------------------');
		    loadSalesforceDataToDB();
		  },
		  start: true,
		  timeZone: 'Pacific/Auckland'
		});
		job.start();

	} catch(ex) {
		console.log(ex);
	}
}

function loadSalesforceDataToDB(){

	console.log('----------------- loadSalesforceDataToDB called -------------------------');

    loadTakiwaDataToDB();
    loadAreaOfInterestToDB();
    loadCommencingStudiesToDB();
			
}

function loadTakiwaDataToDB(){

	var client = new pg.Client(conString);
	client.connect();

	try{

		var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {

	    console.log('result.rowCount=='+result.rowCount);          

	        if(result.rowCount != 0){
		        var row = result.rows[0];

		        var conn_t = new jsforce.Connection({
				  oauth2 : {
				  	loginUrl: row.loginurl,
				    clientId : row.clientid,
				    clientSecret : row.clientsecret,
				    redirectUri : row.redirecturi
				  },
				  instanceUrl : row.instanceurl,
				  accessToken : row.accesstoken,
				  refreshToken : row.refreshtoken
				});

				if(conn_t == null){
					console.log('connection is null');
				}
				else{

					console.log('connection found');
					
					conn_t.describe("Region__c", function(err, meta) {
					  if (err) 
					  { 
					  	console.log('loadTakiwaDataToDB errrrrrrrrrrrrrr'+err);
					  }
					  else{
						  var picklistValues = [];
						  meta.fields.forEach(function(field){
						  	if(field.name == 'Takiwa__c'){
						  		picklistValues = field.picklistValues;	
						  	}
						  })

						 var picklistValues_count = 0;
						 picklistValues.forEach(function(obj){
						 	var query_insert = client.query('insert into takiwa (name) values($1)', [obj.value]);    
					        query_insert.on("end", function (result) {  
					        	picklistValues_count++;
					        	if(picklistValues_count == picklistValues.length){
					        		client.end();	
					        	} 
					        });

					        query_insert.on("error", function (err, result) {  
					        	if(picklistValues_count == picklistValues.length){
					        		client.end();	
					        	}
					        });
						 })
					  }
					});
				}

			}
			else{
				console.log('No Client id or Client secret found, Please specify them first !');
			}	
	    });

		query.on("error", function (err, result) { 
	         
	        console.log('----------------- loadTakiwaDataToDB err  '+err);
	    });
	} catch(ex) {
		client.end();
		console.log('loadTakiwaDataToDB=='+ex);
	}

}

function loadAreaOfInterestToDB(){

	var client = new pg.Client(conString);
	client.connect();

	try{

		var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          

	        if(result.rowCount != 0){
		        var row = result.rows[0];

		        var conn_t = new jsforce.Connection({
				  oauth2 : {
				  	loginUrl: row.loginurl,
				    clientId : row.clientid,
				    clientSecret : row.clientsecret,
				    redirectUri : row.redirecturi
				  },
				  instanceUrl : row.instanceurl,
				  accessToken : row.accesstoken,
				  refreshToken : row.refreshtoken
				});

				if(conn_t == null){
					console.log('connection is null');
				}
				else{
					
					conn_t.describe("Program__c", function(err, meta) {
					  	if (err) { return console.error('loadAreaOfInterestToDB=='+err); }
					  	var areaOfInterests = [];
					  	meta.fields.forEach(function(field){
						  	if(field.name == 'Interest_Category__c'){
						  		areaOfInterests = field.picklistValues;	
						  	}
					  	})

						var picklistValues_count = 0;
						areaOfInterests.forEach(function(obj){
						 	var query_insert = client.query('insert into areaofinterest (interestcategory) values($1)', [obj.value]);    
					        query_insert.on("end", function (result) { 
					        	picklistValues_count++; 
					        	if(picklistValues_count == areaOfInterests.length){
					        		client.end();	
					        	} 
					        });

					        query_insert.on("error", function (err, result) {  
					        	if(picklistValues_count == areaOfInterests.length){
					        		client.end();	
					        	}
					        });
						})
					  
					});
				}
			}
			else{
				console.log('No Client id or Client secret found, Please specify them first !');
			}	
	    });

	} catch(ex) {
		client.end();
		console.log('loadAreaOfInterestToDB=='+ex);
	}
}

function loadCommencingStudiesToDB(){

	var client = new pg.Client(conString);
	client.connect();

	try{

		var query = client.query('select * from public.salesforcredentials where identifier = \''+identifier+'\'');
	    query.on("row", function (row, result) { 
	        result.addRow(row); 
	    });
	    query.on("end", function (result) {          

	        if(result.rowCount != 0){
		        var row = result.rows[0];

		        var conn_t = new jsforce.Connection({
				  oauth2 : {
				  	loginUrl: row.loginurl,
				    clientId : row.clientid,
				    clientSecret : row.clientsecret,
				    redirectUri : row.redirecturi
				  },
				  instanceUrl : row.instanceurl,
				  accessToken : row.accesstoken,
				  refreshToken : row.refreshtoken
				});

				if(conn_t == null){
					console.log('connection is null');
				}
				else{
					
					conn_t.describe("Lead", function(err, meta) {
					  if (err) 
					  { 
					  	console.log('errrrrrrrrrrrrrr'+err);
					  }
					  else{
						  var CommencingStudys = [];
						  meta.fields.forEach(function(field){
						  	if(field.name == 'Commencing_Studies__c'){
						  		CommencingStudys = field.picklistValues;	
						  	}
						  })

						  var picklistValues_count = 0;
						  CommencingStudys.forEach(function(obj){
						 	var query_insert = client.query('insert into commencingstudy (commencing_study) values($1)', [obj.value]);    
					        query_insert.on("end", function (result) {  
					        	picklistValues_count++;
					        	if(picklistValues_count == CommencingStudys.length){
					        		client.end();	
					        	} 
					        });

					        query_insert.on("error", function (err, result) {  
					        	if(picklistValues_count == CommencingStudys.length){
					        		client.end();	
					        	}
					        });
						 })
					  }
					});
				}
			}
			else{
				console.log('No Client id or Client secret found, Please specify them first !');
			}	
	    });
	} catch(ex) {
		client.end();
		console.log('loadCommencingStudiesToDB =='+ex);
	}
}