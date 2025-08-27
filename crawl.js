function getURLsFromHTML(htmlBody,baseURL){
    const urls=[];
    return urls;
}

function normalizeUrl(UrlString){
    const urlObj=new URL(UrlString);


    const hostPath= `${urlObj.host}${urlObj.pathname}`;
if(hostPath.length>0 && hostPath.slice(-1)==='/'){
    return hostPath.slice(0,-1);
}
return hostPath;
}

module.exports={
    normalizeUrl,
    getURLsFromHTML
}