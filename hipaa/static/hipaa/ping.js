/*
 * Sends a ping to the site every once in a while, so your session doesn't expire
 */
$(document).ready(function(){
    // the date we last detected any activity on the page
    var last_activity = new Date();
    // the last thing a ping went out
    var last_ping = new Date();
    // when the state goes from authenticated to unauthenticated, we should
    // reload the page, since that will redirect them to the login page (since
    // they got logged out)
    var state = "unauthenticated";
    var DEFAULT_RETRY_DELAY = 8000;
    var retry_delay = DEFAULT_RETRY_DELAY;

    // The message to display when a logout is coming soon. thanks http://howtocenterincss.com/
    var message = '\
        <div style="display:table;width:100%;height:100%">\
          <div style="display:table-cell;vertical-align:middle;">\
            <div style="text-align:center; font-size:24px; background-color:#ffff00; cursor:pointer; padding:20px">Are you still around? You are about to be logged out. Click anywhere in this box to stay logged in.</div>\
          </div>\
        </div>\
    '

    // detect any activity on the page
    $('body').on("mousemove click keyup scroll", function(){
        last_activity = new Date();
    });

    var ping = function(){
        // was there any activity?
        var was_activity = +(last_activity > last_ping)

        // send a ping so the StillAliveMiddleware can update the
        // HIPAA_LAST_PING session variable
        $.ajax({
            // we can send the ping to this same page, since the middleware
            // will intercept any request
            'url': window.location,
            'headers': {'X-HIPAA-PING': was_activity},
            'cache': false  // see http://stackoverflow.com/a/25230377/2733517
        }).fail(function(){
            // use exponential back-off when the request fails, up to a minute
            setTimeout(ping, retry_delay)
            retry_delay = Math.min(retry_delay*2, 60*1000)
        }).done(function(response){
            // reset the retry_delay since we're back to normal
            retry_delay = DEFAULT_RETRY_DELAY;
            // if there was a transition from being authenticated to being
            // unauthenticated, then reload the page (which will trigger a
            // redirect to the login via some Django middleware)
            if(state == "authenticated" && response.state != "authenticated"){
                location.reload(true);
            }
            state = response.state
            if(response.seconds_until_next_ping <= response.show_logout_warning_before && $('#hipaa-ping-warning').length == 0){
                var div = $("<div>")
                div.attr("id", "hipaa-ping-warning")
                div.css({
                    "position": "absolute",
                    "left": "0",
                    "top": "0",
                    "right": "0",
                    "bottom": "0",
                    "zindex": "100000",
                    "background": "rgba(255, 255, 255, .5)",
                })
                div.html(message)
                div.click(function(){
                    $(this).remove();
                    // a click will trigger our body click handler which
                    // will update last_activity
                })
                $('body').append(div)
            }
            setTimeout(ping, response.seconds_until_next_ping*1000)
        }),
        last_ping = new Date();
    }

    ping()
});
