

setTimeout(function() { // avoid java.lang.ClassNotFoundException

const className = "android.app.Activity";

Java.perform(function() {
	var classLoad = Java.use(className);
	console.log(classLoad);

	classLoad.onCreate.overload("android.os.Bundle").implementation = function (var_0) {
		// Show a message to know that the function got called
		send('addFlags : ' + var_0);
i
    // Call the original onClick handler
		this.onCreate.overload("android.os.Bundle").call(this,var_0);
	};
});

},0);
