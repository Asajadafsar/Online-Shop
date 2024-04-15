import {
  Admin,
  Resource,
  ListGuesser,
  EditGuesser,
  ShowGuesser,
} from "react-admin";
import  dataProvider  from "./dataProvider";
import { authProvider } from "./authProvider";
import { CustomersList } from "./Customers";
import {AdminList } from "./Admin";
import {logsList } from "./Logs";
import { CustomerCreate,ProductCreate,CategoryCreate } from "./Create";
import { ProductsList } from "./Products";
import { CategoryList,CategoryShow ,CategoryEdit} from "./Category";
import { OrderEdit, OrderList, OrderShow } from "./Order";
import {FeedbackList } from "./Feedbacks";
import {Adresslist } from "./ShippingAddressList";
import {PaymentList } from "./Payment";
import Dashboard from './Dashboard'; 
export const App = () => (
  <Admin dataProvider={dataProvider} authProvider={authProvider}   dashboard={Dashboard}>
    <Resource
      name="admin"
      list={AdminList}
      edit={EditGuesser}
      show={ShowGuesser}
      create={CustomerCreate}
    />
    <Resource
      name="customer"
      list={CustomersList}
      edit={EditGuesser}
      show={ShowGuesser}
      create={CustomerCreate}
    />
    <Resource
      name="products"
      list={ProductsList}
      edit={EditGuesser}
      show={ShowGuesser}
      create={ProductCreate}
/>

     <Resource
      name="categories"
      list={CategoryList}
      edit={CategoryEdit}
      show={CategoryShow}
      create={CategoryCreate}
    />
    <Resource
      name="orders"
      list={OrderList}
      edit={OrderEdit}
      show={OrderShow}
    />
    <Resource
      name="logs"
      list={logsList}
      show={ShowGuesser}
    />
    <Resource
      name="ShippingAddress"
      list={Adresslist}
      edit={EditGuesser}
      show={ShowGuesser}
    />
    <Resource
      name="feedbacks"
      list={FeedbackList}
      edit={EditGuesser}
      show={ShowGuesser}
    />
        <Resource
      name="payment"
      list={PaymentList}
      edit={EditGuesser}
      show={ShowGuesser}
    />
  </Admin>
);