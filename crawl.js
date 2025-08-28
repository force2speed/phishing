const {JSDOM}=require('jsdom')
async function crawlPage(baseURL,currentURL,pages)
{
    
    
    const baseURLObj=new URL(baseURL);
    const currentURLObj=new URL(currentURL);    
    if(baseURLObj.hostname!==currentURLObj.hostname){
        return pages;
    }
    
    const normalizedCurrentURL=normalizeUrl(currentURL);
    if(pages[normalizedCurrentURL]>0){
        pages[normalizedCurrentURL]++;  
        return pages;
    }
    pages[normalizedCurrentURL]=1;
    console.log(`Actively Crawling ${currentURL}`);
    try {
        
        const resp=await fetch(currentURL);
        if(resp.status>399){
            console.log(`error in fetch with status code: ${resp.status} on page  ${currentURL}`); 
            return pages;
        }
        const contentType=resp.headers.get("content-type");
        if(!contentType.includes("text/html")){
            console.log.log(`non html response, content type: ${contentType} on page  ${currentURL}`);  
            return pages
        }
        const htmlBody=await resp.text();//already have geturls from html which will just take this text
        const nextURLs=getURLsFromHTML(htmlBody,baseURL);
        for(const nextURL of nextURLs){
            pages=await crawlPage(baseURL,nextURL,pages);
        }   
    } catch (error) {
            console.log(`error in fetch: ${error.message} on page  ${currentURL}`);
    }
    return pages;

}
function getURLsFromHTML(htmlBody,baseURL){
    const urls=[];
    const dom=new JSDOM(htmlBody);
    const linkElements=dom.window.document.querySelectorAll('a');
    for(const linkElement of linkElements){
        if(linkElement.href.slice(0,1)==='/'){
            try{

                const urlObj=new URL(`${baseURL}${linkElement.href}`);
                urls.push(urlObj.href);
            }    
            catch(err){
                console.log(`error with relative url: ${err.message}`);
            }

        }
        else{
             try{

                const urlObj=new URL(linkElement.href);
                urls.push(urlObj.href);
            }    
            catch(err){
                console.log(`error with absolute url: ${err.message}`);
            }
        }
    }
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
    getURLsFromHTML,
    crawlPage
}