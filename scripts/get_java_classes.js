//setTimeout(function() { // avoid java.lang.ClassNotFoundException

const webviewClassName = 'android.webkit.WebView';
const javascriptInterfaceClassName = 'com.facebook.ads.a.r';
const URLclassName = 'java.net.URL';

Java.perform(function() {
  var classes = Java.enumerateLoadedClassesSync();
  var count = 0
  classes.forEach(function(klass) {
    if (klass.indexOf('com.android') !== -1 || klass.indexOf('an')) {
      console.log(klass);
	    count++
    }
  });
	console.log(count)
});

//},0);
