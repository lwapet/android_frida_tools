//setTimeout(function() { // avoid java.lang.ClassNotFoundException

const className = 'android.webkit.WebView';

Java.perform(function() {
  var klass = Java.use(className);
  console.log(klass);

  klass.reload.overload().implementation = function (var_0) {
    var that = this;
    // Show a message to know that the function got called
    send('webview : ' + var_0);
    Java.perform(function() {
      console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
    });
    // Call the original onClick handler
    this.reload.overload().call(this,var_0);
  };

});

//},0);
