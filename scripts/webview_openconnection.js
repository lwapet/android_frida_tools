

//setTimeout(function() { // avoid java.lang.ClassNotFoundException

const webviewClassName = "android.webkit.WebView";
const URLclassName = "java.net.URL";

Java.perform(function() {
	var webviewClass = Java.use(webviewClassName);
	console.log(webviewClass);

	webviewClass.loadUrl.overload("java.lang.String").implementation = function (var_0) {
		// Show a message to know that the function got called
		send('webview' + var_0);

    // Call the original onClick handler
		this.loadUrl.overload("java.lang.String").call(this,var_0);
	};

	// var urlClass = Java.use(URLclassName);
	// console.log(urlClass);
  //
  // urlClass.openConnection.overload().implementation = function() {
		// send('openConnection');
    //
    // var retval = this.openConnection.overload().call(this);
    // return retval;
	// }

	// urlClass.$init.overload("java.lang.String").implementation = function(var_0) {
	// 	var payload = {'url': var_0}
	// 	send (JSON.stringify(payload));
  //
		// Java.perform(function() {
		// 	console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
		// });
    //
    // var retval = this.$init.overload("java.lang.String").call(this, var_0);
    // return retval;
	// }
});

//},0);
