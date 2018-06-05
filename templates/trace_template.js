'use strict';

function decryptValue(valueToDecrypt, valueType) {
  if(!valueToDecrypt) {
    return null;
  }
  if(typeof valueToDecrypt === 'object' && '$handle' in valueToDecrypt) {
    Java.perform(function() {
      var valueTypeClass = Java.use(valueType)
      return Java.cast(ptr(valueToDecrypt.$handle), valueTypeClass).toString();
    });
  } else {
    return valueToDecrypt.toString();
  }
}
//*added by Lavoisier*//
function callHooksFun() { //Defining the function that will be exported
	Java.perform(function() {
		  {% for  method_hook  in  method_hooks  %}
		  {{ method_hook }}
		  {% endfor %}
		});
}



rpc.exports = {
	    callhooksfunction: callHooksFun //exporting callSecretFun as callsecretfunction
	  // the name of the export (callsecretfunction) cannot have  neither Uppercase letter nor uderscores.
};


/*Java.perform(function() {
  {% for  method_hook  in  method_hooks  %}
  {{ method_hook }}
  {% endfor %}
});
*/