import agentflow from './agent-flow.png';
import '../Style/App.css'

export function AboutPage() {
    return (
        <>
            <div className="sub-container static-box">
                <h2 className="static title">About Us：</h2>
                <p className="static text">We are two college interns, from UPenn and Penn State, currently working at TransformaTech. We are both incredibly passionate about working with new technologies and our goal is to take what we have learned in integration to get the most out of IBM’s Artificial Intelligence. :3</p>

                <h2 className="static title">About our problem:</h2>
                <p className="static text">With the rapid technological developments, many small companies are struggling to keep up and with this, their cybersecurity tends to fall short as well. In fact, according to Information Security Engineer <a href="https://www.getastra.com/blog/author/rishabh/">Rishabh Goyal</a>, 43% of cyber attacks are aimed at small businesses, whereas only 14% are prepared to defend themselves. Our mission is to create an AI solution that emulates an entire team of cybersecurity experts in a much more cost effective and accessible way.</p>
            </div>
        </>
    );
}

export function FunctionalityPage() {
    return (
        <>
            <div className="sub-container static-box">
                <h2>Functionality:</h2>
                <img className="centered" src={agentflow} style={{height:'auto', width:'30vw', marginLeft:'20vw'}}></img>
                <p className="static text">The User communicates with the cybersecurity manager over API which then starts the initial screening, informing the user on possible next steps. Depending on the next steps, the manager will call specific agents who are experts in specific fields and will perform tests in their specific areas.</p>

                <div className="static text left">
                    Tools:
                    <ul className="static list">
                        <li><a href="https://github.com/sullo/nikto">Nikto</a>
                        <ul><li>Safe initial screening to determine preliminary vulnerabilities</li></ul></li>
                        <li><a href="https://sqlmap.org/">Sqlmap</a>
                        <ul><li>Targeted SQL Injection detection</li></ul></li>
                        <li><a href="https://www.zaproxy.org/">OWASP Zap</a>
                        <ul><li>Web app scanner with many targeted modules</li></ul></li>
                    </ul>
                </div>

            </div>
        </>
    );
}