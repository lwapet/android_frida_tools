//setTimeout(function() { // avoid java.lang.ClassNotFoundException

const webviewClassName = 'android.webkit.WebView';
const javascriptInterfaceClassName = 'com.facebook.ads.a.r';
const URLclassName = 'java.net.URL';

Java.perform(function() {
  var javascriptInterfaceClass = Java.use(javascriptInterfaceClassName);
  var webviewClass = Java.use(webviewClassName);
  console.log(webviewClass);

  webviewClass.addJavascriptInterface.overload('java.lang.Object',
      'java.lang.String').implementation = function(var_0, var_1) {
    send('add JS interface called');
    send('v0 : ' + var_0);
    send('v1 : ' + var_1);

    var retval = this.addJavascriptInterface.overload('java.lang.Object',
        'java.lang.String').call(this, var_0, var_1);
    send('retval : ' + retval)
    return retval;
  };

  // javascriptInterfaceClass.getAnalogInfo.overload().implementation = function () {
  //     Show a message to know that the function got called
  // send('get contacts called');
  //
  // Call the original onClick handler
  // var retval = this.getAnalogInfo.overload().call(this);
  // send('retval' + retval);
  // return retval;
  // };
});

//},0);
