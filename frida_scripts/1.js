Java.perform(function() {
    var targets = [];
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().indexOf('https') >= 0 || 
                className.toLowerCase().indexOf('okhttp') >= 0 ||
                className.toLowerCase().indexOf('socket') >= 0 ||
                className.toLowerCase().indexOf('connection') >= 0) {
                targets.push(className);
            }
        },
        onComplete: function() {
            console.log(JSON.stringify(targets, null, 2));
        }
    });
});