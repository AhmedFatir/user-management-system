import './local-game-match-result.css'
import './matchresult.css'
import avatar from "../../../assets/avatar4.png"
import winnerImg from "../asstes/winner.png"
import { useTranslation } from 'react-i18next'

const LocalGameMatchResult = ({winner, winnerAvatar, onBack}) => {
    const { t } = useTranslation();
    return (
        <div className="match-result">
            <img 
                src={avatar} 
                alt="User Avatar" 
                className='local-winner winner' 
            />
            <h1 className='winer-username'>{winner}</h1>
            <h1 className="resultTitre">{t('YOU WON')}<img src={winnerImg} alt="" className="something"/></h1>
            <button onClick={onBack} className="backToLobby">{t('Back To Lobby')}</button>
        </div>
    );
}
 
export default LocalGameMatchResult;