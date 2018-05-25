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

Java.perform(function() {
  {% for  method_hook  in  method_hooks  %}
  {{ method_hook }}
  {% endfor %}
});
