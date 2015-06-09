/*
 * Sends a ping to the site every HIPAA_MILLISECONDS_BETWEEN_PINGS milliseconds
 * (or 5 minutes by default)
 */
$(document).ready(function(){
    // this should be about half of the AUTOMATIC_LOGOUT_AFTER time
    // 5 minutes is reasonable for most configurations
    var milliseconds_between_pings = HIPAA_MILLISECONDS_BETWEEN_PINGS || 1000*60*5;
    // the date we last detected any activity on the page
    var last_activity = new Date();
    // the last thing a ping went out
    var last_ping = new Date();

    // detect any activity on the page
    $('body').on("mousemove click keyup scroll", function(){
        last_activity = new Date();
    });

    setInterval(function(){
        // was there any activity?
        var was_activity = +(last_activity > last_ping)

        // send a ping so the StillAliveMiddleware can update the
        // HIPAA_LAST_PING session variable
        $.ajax({
            // we can send the ping to this same page, since the middleware
            // will intercept any request
            'url': window.location,
            'headers': {'X-HIPAA-PING': was_activity},
            'success': function(data){
                // if the response we get back is not ok, then the session
                // expired, and we reload the page (which will force a redirect
                // to the login page)
                if(data != "ok"){
                    location.reload(true);
                }
            },
        });
        last_ping = new Date();
    }, milliseconds_between_pings);
});
