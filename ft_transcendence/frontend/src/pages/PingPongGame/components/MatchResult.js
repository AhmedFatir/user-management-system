import "./matchresult.css";
import useFetch from "../../../hooks/useFetch";
import { useEffect, useState } from "react";
import winnerImg from "../asstes/winner.png";
import sad from "../asstes/sad.png";
import { useTranslation } from 'react-i18next'



const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const MatchResult = ({ winner, onBack }) => {
    const [profileData, setProfileData] = useState(null);
    const { data, error, isLoading } = useFetch(`${BACKEND_URL}/user/stats`);
    const { t } = useTranslation();

    useEffect(() => {
        if (data) {
            setProfileData(data);
        }
    }, [data]);

    return (
        <div className="match-result">
            {profileData && profileData.avatar && profileData.username && (
                <>
                <img 
                    src={`${BACKEND_URL}${profileData.avatar}`} 
                    alt="User Avatar" 
                    className={`user-avatar ${profileData.username === winner ? 'winner' : 'loser'}`} 
                />
                <h1>{profileData.username}</h1>
                </>
            )}
            {profileData && profileData.username && profileData.username === winner ? (
                <>
                    <h1 className="winnerXP">+50PX</h1>
                    <h1 className="resultTitre">{t('YOU WON')}<img src={winnerImg} alt="" className="something"/></h1>
                </>
            ) : (
                <>
                    <h1 className="loserXP">-20XP</h1>
                    <h1 className="resultTitre">{t('Good Luck Next Time')}<img src={sad} alt="" className="something"/></h1>
                </>
            )}
            <button onClick={onBack} className="backToLobby">{t('Back To Lobby')}</button>
        </div>
    );
};

export default MatchResult;
