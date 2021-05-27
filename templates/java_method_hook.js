try {
  Java.use("{{ class_name }}").{{ method_name }}.overload({{ parameters|join(', ') }}).implementation = function({{ arguments|join(', ') }}) {
    {% if arguments|length > 0 -%}
    {% set this="this," -%}
    {% else -%}
    {% set this="this" -%}
    {% endif -%}

    var return_value = this.{{ method_name }}.overload({{ parameters|join(', ') }}).call({{ this }}{{arguments|join(', ') }});
    var decryptedReturnValue = decryptValue(return_value, "{{ return_value }}");

    var args = [{{ arguments|j(', ')oin }}];
    var decryptedArgs = [];
    args.forEach(function(arg, i) {
      var parameters = [{{ parameters|join(', ') }}];
      var decryptedArgValue = decryptValue(arg, parameters[i]);
      decryptedArgs.push(decryptedArgValue);
    });

    var methodStackTrace = "";
    Java.perform(function() {
      methodStackTrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
    });

    var payload = {
      class_name: "{{ class_name }}",
      method_name: "{{ method_name }}",
      args: decryptedArgs,
      return_value: decryptedReturnValue,
      stack_trace: methodStackTrace
    };
    send(JSON.stringify(payload));

    return return_value;
  };
} catch (err) {
  console.log(err)
}


