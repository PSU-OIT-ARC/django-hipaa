/*
 * Sends a ping to the site every HIPAA_MILLISECONDS_BETWEEN_PINGS milliseconds
 * (or 5 minutes by default)
 */
$(document).ready(function(){
    // this should be about half of the AUTOMATIC_LOGOUT_AFTER time
    // 5 minutes is reasonable for most configurations
    var milliseconds_between_pings = typeof(HIPAA_MILLISECONDS_BETWEEN_PINGS) === "undefined" ? 1000*60*5 : HIPAA_MILLISECONDS_BETWEEN_PINGS;
    // the date we last detected any activity on the page
    var last_activity = new Date();
    // the last thing a ping went out
    var last_ping = new Date();
    // when the state goes from authenticated to unauthenticated, we should
    // reload the page, since that will redirect them to the login page (since
    // they got logged out)
    var state = "unauthenticated";

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
            'success': function(new_state){
                // if there was a transition from being authenticated to being
                // unauthenticated, then reload the page (which will trigger a
                // redirect to the login via some Django middleware)
                if(state == "authenticated" && new_state != "authenticated"){
                    location.reload(true);
                }
                state = new_state
            },
        });
        last_ping = new Date();
    }, milliseconds_between_pings);
});
