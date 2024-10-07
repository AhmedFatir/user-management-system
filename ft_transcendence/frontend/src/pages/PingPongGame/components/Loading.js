import { useEffect, useState } from "react";
import LoadingIMG from "../asstes/loading.svg";
import { useTranslation } from 'react-i18next'


const Loading = () => {
    const [text, setText] = useState('');
    const [showImg, setShowImg] = useState(true);
    const { t } = useTranslation();


    useEffect (() => {
        setTimeout(() =>{
            setText(t('Loading...'));
        }, 3000)
    }, [])
    
    return (
        <div className="loading-container">
            {
                showImg ? (
                    <img src={LoadingIMG} alt="loading"/>
                ) : (
                    <h3>{text}</h3>
                )
            }
        </div>    
    );
}
 
export default Loading;