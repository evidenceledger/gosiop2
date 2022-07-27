// **************************************
// Functions supporting the camera
// **************************************

// Get the OS of the device
export function getPlatformOS() {
    const userAgent = window.navigator.userAgent;
    let os = null;

    const isIOS = (/iPad|iPhone|iPod/.test(userAgent) ||
        (/Mac|Mac OS|MacIntel/gi.test(userAgent) && (navigator.maxTouchPoints > 1 || "ontouchend" in document))) && !window.MSStream;

    if (/Macintosh|Mac|Mac OS|MacIntel|MacPPC|Mac68K/gi.test(userAgent)) {
        os = 'Mac OS';
    } else if (isIOS) {
        os = 'iOS';
    } else if (/'Win32|Win64|Windows|Windows NT|WinCE/gi.test(userAgent)) {
        os = 'Windows';
    } else if (/Android/gi.test(userAgent)) {
        os = 'Android';
    } else if (/Linux/gi.test(userAgent)) {
        os = 'Linux';
    }

    return os;
}
console.log(getPlatformOS())

export async function getVideoDevices() {
    // Returns an array of video devices or undefined if none

    // Get the video devices
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        console.log("enumerateDevices() not supported.");
        return undefined;
    }

    let allDevices = await navigator.mediaDevices.enumerateDevices()
    let videoDevices = allDevices.filter((device) => {
        return device.kind === "videoinput";
    });
    console.log(videoDevices)
    if (videoDevices.length == 0) {
        return undefined;
    }

    // Check if they have labels. If they don't, it means we have to request permission from the user
    let allLabelsEmpty = videoDevices.every((device) => { return device.label === "" })
    if (!allLabelsEmpty) {
        return videoDevices;
    }

    let stream;
    try {
        // Request a stream to force the system to ask the user
        stream = await navigator.mediaDevices.getUserMedia({
            video: true,
            audio: false,
        });
        // Try again to get the devices with label and id information
        allDevices = await navigator.mediaDevices.enumerateDevices()
        videoDevices = allDevices.filter((device) => {
            return device.kind === "videoinput";
        });
    }
    catch {
        // Ignored
        console.log("Probably the user did not authorise request")
    } finally {
        // Release resources if the previous call was successful
        if (stream !== undefined) {
            stream.getVideoTracks().forEach((track) => {
                track.stop();
            });
        }
    }
    return videoDevices
}

export async function getPreferredVideoDevice() {

    // Prepare undefined response
    let undefinedVideoDevice = {
        defaultPreferredCamera: undefined,
        videoDevices: []
    }

    // Get all video devices, front and back
    let videoDevices = await getVideoDevices()
    if (!videoDevices) {
        return undefinedVideoDevice;
    }

    let defaultPreferredCamera;

    // Select specific device only for Android devices
    if ("Android" == getPlatformOS()) {
        // The main recommended back camera is the last one in the list
        defaultPreferredCamera = videoDevices[videoDevices.length - 1]
    }

    return {
        defaultPreferredCamera: defaultPreferredCamera,
        videoDevices: videoDevices
    }

}
