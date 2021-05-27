
//*added by Lavoisier* (I just moved the java.perform function in a callHooksFunctions exported by rpc//
function callHooksFun() { //Defining the function that will be exported
	Java.perform(function() {
    var patterns = [
      {% for  pattern  in  patterns -%}
      {{ pattern }},
      {% endfor -%}
    ];
  
    function wildcard_search(string, search) {
      var prevIndex = -1,
          array = search.split('*'),
          result = true;
      for (var i = 0; i < array.length && result; i++) {
        var index = string.indexOf(array[i]);
        if (index == -1 || index < prevIndex) {
          return false;
        }
      }
      return result;
    }
  
    Java.enumerateLoadedClasses({
      onMatch: function(name) {
        name = name.replace(/\//gi, '.').replace(/\[/gi, '').replace(/^L/, '').replace(/;$/, '');
        patterns.forEach(function(pattern) {
          if (wildcard_search(name, pattern.class_name)) {
            try {
              var handle = Java.use(name);
              var currentMethods = handle.class.getMethods();
              currentMethods.forEach(function(active_method_name) {
                var signature = active_method_name.toString();
                var args = signature.split('(')[1].split(')')[0]
                var args_array = args.split(',')
                var full_method_name = signature.split('(')[0];
                full_method_name_array = full_method_name.split(' ');
                full_method_name = full_method_name_array[full_method_name_array.length - 1]
                var return_type = full_method_name_array[full_method_name_array.length - 2]
                var lastDot = full_method_name.lastIndexOf('.');
                var class_name = full_method_name.substring(0, lastDot)
                var method_name = full_method_name.substring(lastDot + 1, full_method_name.length);
                pattern.method_names.forEach(function(pattern_method) {
                  if (wildcard_search(method_name, pattern_method)) {
                    var payload = {
                      class_name : class_name,
                      method_name: method_name,
                      parameters: args_array,
                      return_type: return_type
                    }
                    send(JSON.stringify(payload));
                  }
                });
  
                // pattern.method_names.forEach(function(method_name) {
                //   if(wildcard_search(active_method_name, method_name)) {
                //     console.log(method_name)
                //   }
                // });
              });
            } catch (e) {
              console.log(e)
            }
  
          }
        })
      },
      onComplete: function() {
        var payload = {
          system_message : 'script_finished',
        }
        send(JSON.stringify(payload));
      }
    });
  });
  
}



rpc.exports = {
	    callhooksfunction: callHooksFun //exporting callSecretFun as callsecretfunction
	  // the name of the export (callsecretfunction) cannot have  neither Uppercase letter nor uderscores.
};


/*Java.perform(function() {
  var patterns = [
    {% for  pattern  in  patterns -%}
    {{ pattern }},
    {% endfor -%}
  ];

  function wildcard_search(string, search) {
    var prevIndex = -1,
        array = search.split('*'),
        result = true;
    for (var i = 0; i < array.length && result; i++) {
      var index = string.indexOf(array[i]);
      if (index == -1 || index < prevIndex) {
        return false;
      }
    }
    return result;
  }

  Java.enumerateLoadedClasses({
    onMatch: function(name) {
      name = name.replace(/\//gi, '.').replace(/\[/gi, '').replace(/^L/, '').replace(/;$/, '');
      patterns.forEach(function(pattern) {
        if (wildcard_search(name, pattern.class_name)) {
          try {
            var handle = Java.use(name);
            var currentMethods = handle.class.getMethods();
            currentMethods.forEach(function(active_method_name) {
              var signature = active_method_name.toString();
              var args = signature.split('(')[1].split(')')[0]
              var args_array = args.split(',')
              var full_method_name = signature.split('(')[0];
              full_method_name_array = full_method_name.split(' ');
              full_method_name = full_method_name_array[full_method_name_array.length - 1]
              var return_type = full_method_name_array[full_method_name_array.length - 2]
              var lastDot = full_method_name.lastIndexOf('.');
              var class_name = full_method_name.substring(0, lastDot)
              var method_name = full_method_name.substring(lastDot + 1, full_method_name.length);
              pattern.method_names.forEach(function(pattern_method) {
                if (wildcard_search(method_name, pattern_method)) {
                  var payload = {
                    class_name : class_name,
                    method_name: method_name,
                    parameters: args_array,
                    return_type: return_type
                  }
                  send(JSON.stringify(payload));
                }
              });

              // pattern.method_names.forEach(function(method_name) {
              //   if(wildcard_search(active_method_name, method_name)) {
              //     console.log(method_name)
              //   }
              // });
            });
          } catch (e) {
            console.log(e)
          }

        }
      })
    },
    onComplete: function() {
      var payload = {
        system_message : 'script_finished',
      }
      send(JSON.stringify(payload));
    }
  });
});
*/