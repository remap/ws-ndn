console.log("starting websocket...");
if ("WebSocket" in window) {
    var ws = new WebSocket("ws://localhost:5001");
    ws.onopen = function() {
        console.log("WebSockets connection opened");
        ws.send("Hello Server (from client)");
    }
    ws.onmessage = function(e) {
        console.log("Got from server: " + e.data);
    }
    ws.onclose = function() {
        console.log("WebSockets connection closed");
    }
} else {
    alert("No WebSockets support");
}

