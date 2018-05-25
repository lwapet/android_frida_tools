var methods = []
Java.perform(function() {
  Java.enumerateLoadedClasses({
    onMatch: function(name) {
      var javaClass = Java.use(name);
      var methods = javaClass.class.getMethods();
      methods.forEach(function(name) {
        methods.put(name);
        send(name)
      })
    },
    onComplete: function() {
      send(methods)
    }
  });
});
