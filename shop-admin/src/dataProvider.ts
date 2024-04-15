import axios from 'axios';
import { stringify } from 'query-string';
import { DataProvider, fetchUtils, CreateParams, CreateResult } from 'react-admin';

const apiUrl = 'http://localhost:5000';

interface Product {
    id?: number;
    name: string;
    description: string;
    price: number;
    category_id: number;
    image?: File;
}



const httpClient = axios.create({
  baseURL: apiUrl,
});

// اضافه کردن Interceptor برای درخواست‌ها
httpClient.interceptors.request.use((config) => {
  // دریافت توکن از localStorage
  const token = localStorage.getItem('token');
  // اضافه کردن توکن به headers در صورت وجود توکن
  if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
  }
  // همچنین می‌توانید هر header دیگری مانند 'Barber' اضافه کنید
  config.headers['Barber'] = 'SomeValue'; // ارزش این هدر باید بر اساس نیاز شما تنظیم شود
  return config;
}, (error) => {
  // برخورد با خطاهای ممکن در ساخت درخواست
  return Promise.reject(error);
});



const dataProvider: DataProvider = {
    getList: (resource, params) => {
        const { page, perPage } = params.pagination;
        const { field, order } = params.sort;
        const query = {
            sort: JSON.stringify([field, order]),
            range: JSON.stringify([(page - 1) * perPage, page * perPage - 1]),
            filter: JSON.stringify(params.filter),
        };
        const url = `/${resource}?${stringify(query)}`;

        return httpClient.get(url).then(response => ({
            data: response.data,
            total: parseInt(response.headers['x-total-count'], 10),
        }));
    },
    getOne: (resource, params) =>
        httpClient.get(`/${resource}/${params.id}`).then(response => ({
            data: response.data,
        })),
    getMany: (resource, params) => {
        const query = {
            filter: JSON.stringify({ id: params.ids }),
        };
        const url = `/${resource}?${stringify(query)}`;
        return httpClient.get(url).then(response => ({
            data: response.data,
        }));
    },
    getManyReference: (resource, params) => {
        const { page, perPage } = params.pagination;
        const { field, order } = params.sort;
        const query = {
            sort: JSON.stringify([field, order]),
            range: JSON.stringify([(page - 1) * perPage, page * perPage - 1]),
            filter: JSON.stringify({ ...params.filter, [params.target]: params.id }),
        };
        const url = `/${resource}?${stringify(query)}`;
        return httpClient.get(url).then(response => ({
            data: response.data,
            total: parseInt(response.headers['x-total-count']),
        }));
    },
    update: (resource, params) =>
        httpClient.put(`/${resource}/${params.id}`, params.data).then(response => ({
            data: response.data,
        })),
        create: (resource, params) => {
          if (resource === 'products' && params.data.image) {
              const formData = new FormData();
              Object.keys(params.data).forEach(key => {
                  if (key === 'image' && params.data[key].rawFile) {
                      // اطمینان از افزودن فایل به `FormData`
                      formData.append(key, params.data[key].rawFile);
                  } else {
                      // تبدیل سایر داده‌ها به رشته و اضافه کردن به `FormData`
                      formData.append(key, params.data[key]);
                  }
              });
              return httpClient.post(`/${resource}`, formData, {
                  headers: { 'Content-Type': 'multipart/form-data' },
              }).then(response => ({ data: { ...params.data, id: response.data.id } }));
          } else {
              // ارسال سایر داده‌ها به صورت JSON
              return httpClient.post(`/${resource}`, params.data).then(response => ({
                  data: { ...params.data, id: response.data.id },
              }));
          }
      },
      
    delete: (resource, params) =>
        httpClient.delete(`/${resource}/${params.id}`).then(response => ({
            data: response.data,
        })),
        deleteMany: (resource, params) => {
    const ids = params.ids;
    const deletePromises = ids.map(id =>
        httpClient.delete(`/${resource}/${id}`)
    );
    return Promise.all(deletePromises).then(responses => ({
        data: responses.map(response => response.data)
    }));
},

};

export default dataProvider;


